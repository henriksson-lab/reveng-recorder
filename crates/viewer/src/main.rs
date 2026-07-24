//! `reveng-viewer` — egui timeline + screenshot pane + traffic inspector (DESIGN.md §9).
//!
//! Select a checkpoint (click, or ←/→ to step); the screenshot at that instant and the
//! traffic frames in a window around it update together. The data plumbing lives in
//! [`model`] (unit-tested); this file is the thin egui shell.

mod model;

use clap::Parser;
use eframe::egui;
use model::{type_color, SessionModel};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "reveng-viewer", version, about = "Session timeline / traffic inspector")]
struct Cli {
    /// Session directory to open.
    session: PathBuf,
    /// Overlay a UIA control's value across the timeline (e.g. "Exposure Time"), read from
    /// each checkpoint's `ui/<id>.json` — the semantic value curve alongside traffic density.
    #[arg(long)]
    track: Option<String>,
}

/// Paint a value-track sparkline: one point per checkpoint (evenly spaced to match the tick row),
/// normalized 0..1, joined by lines; gaps (`None`) break the line. No-op for an all-empty track.
fn draw_value_track(ui: &mut egui::Ui, track: &[Option<f32>], h: f32, label: &str) {
    if track.iter().all(|v| v.is_none()) {
        return;
    }
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), h), egui::Sense::hover());
    let n = track.len().max(1);
    let x_of = |i: usize| rect.left() + (i as f32 + 0.5) * rect.width() / n as f32;
    let y_of = |v: f32| rect.bottom() - v.clamp(0.0, 1.0) * (h - 4.0) - 2.0;
    let color = egui::Color32::from_rgb(240, 200, 90);
    let mut prev: Option<egui::Pos2> = None;
    for (i, v) in track.iter().enumerate() {
        match v {
            Some(v) => {
                let p = egui::pos2(x_of(i), y_of(*v));
                if let Some(pp) = prev {
                    ui.painter().line_segment([pp, p], egui::Stroke::new(1.5, color));
                }
                ui.painter().circle_filled(p, 2.0, color);
                prev = Some(p);
            }
            None => prev = None,
        }
    }
    ui.painter().text(
        rect.left_top() + egui::vec2(2.0, 0.0),
        egui::Align2::LEFT_TOP,
        label,
        egui::FontId::proportional(10.0),
        color,
    );
}

/// Paint one traffic-density strip: a full-width histogram, bar height + colour intensity ∝
/// bucket count. No-op for an empty strip.
fn draw_density_strip(ui: &mut egui::Ui, bins: &[u32], h: f32, color: impl Fn(u8) -> egui::Color32) {
    if bins.is_empty() {
        return;
    }
    let max = (*bins.iter().max().unwrap_or(&1)).max(1) as f32;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), h), egui::Sense::hover());
    let bw = rect.width() / bins.len() as f32;
    for (i, &c) in bins.iter().enumerate() {
        let frac = c as f32 / max;
        let x = rect.left() + i as f32 * bw;
        let bar = egui::Rect::from_min_max(
            egui::pos2(x, rect.bottom() - h * frac),
            egui::pos2(x + bw.max(1.0), rect.bottom()),
        );
        let shade = (60.0 + 180.0 * frac) as u8;
        ui.painter().rect_filled(bar, 0.0, color(shade));
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let model = SessionModel::open(&cli.session)?;

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1200.0, 800.0]),
        ..Default::default()
    };
    eframe::run_native(
        "reveng-viewer",
        options,
        Box::new(move |_cc| Ok(Box::new(App::new(model, cli.track)))),
    )
    .map_err(|e| anyhow::anyhow!("viewer failed: {e}"))
}

struct App {
    model: SessionModel,
    sel: usize,
    window: u64,
    rows: Vec<model::InspectorRow>,
    secondary_rows: Vec<model::InspectorRow>,
    tex: Option<egui::TextureHandle>,
    loaded_for: Option<usize>,
    /// Traffic density buckets across the whole capture (timeline overlay), computed once.
    /// `density` = primary source; `density_pcie` = co-logged PCIe (empty if none).
    density: Vec<u32>,
    density_pcie: Vec<u32>,
    /// Optional UIA value track (`--track`): one normalized value per checkpoint, and its label.
    track: Vec<Option<f32>>,
    track_label: String,
}

impl App {
    fn new(mut model: SessionModel, track_control: Option<String>) -> Self {
        let (density, density_pcie) = model.traffic_density_split(120);
        let (track, track_label) = match &track_control {
            Some(name) => (model::normalize_track(&model.value_track(name)), name.clone()),
            None => (Vec::new(), String::new()),
        };
        Self {
            model,
            sel: 0,
            window: 20,
            rows: Vec::new(),
            secondary_rows: Vec::new(),
            tex: None,
            loaded_for: None,
            density,
            density_pcie,
            track,
            track_label,
        }
    }

    /// (Re)load the inspector rows + screenshot texture for the current selection.
    fn reload(&mut self, ctx: &egui::Context) {
        if self.model.checkpoints.is_empty() {
            self.loaded_for = Some(self.sel);
            return;
        }
        let ckpt = self.model.checkpoints[self.sel].clone();
        self.rows = self.model.frames_around(&ckpt, self.window).unwrap_or_default();
        self.secondary_rows = self.model.secondary_rows(&ckpt).unwrap_or_default();

        self.tex = None;
        if let Some(path) = self.model.screenshot_path(&ckpt) {
            if let Ok(img) = image::open(&path) {
                let rgba = img.to_rgba8();
                let (w, h) = rgba.dimensions();
                let color = egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba);
                self.tex = Some(ctx.load_texture("screenshot", color, Default::default()));
            }
        }
        self.loaded_for = Some(self.sel);
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let n = self.model.checkpoints.len();

        // Keyboard seek: ←/→ step between checkpoints.
        if n > 0 {
            ctx.input(|i| {
                if i.key_pressed(egui::Key::ArrowRight) && self.sel + 1 < n {
                    self.sel += 1;
                }
                if i.key_pressed(egui::Key::ArrowLeft) && self.sel > 0 {
                    self.sel -= 1;
                }
            });
        }
        if self.loaded_for != Some(self.sel) {
            self.reload(&ctx);
        }

        egui::Panel::top("top").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("reveng-viewer");
                ui.separator();
                ui.label(format!(
                    "source: {}   frames: {}   checkpoints: {}",
                    self.model.source, self.model.total_frames, n
                ));
            });
        });

        // Timeline strip: one coloured tick per checkpoint, click to select.
        egui::Panel::top("timeline").show(ui, |ui| {
            // Traffic-density overlay: busy regions of the whole capture at a glance. Primary
            // source in teal; co-logged PCIe (if any) in a thinner purple strip below, on the
            // same time axis.
            draw_density_strip(ui, &self.density, 18.0, |s| egui::Color32::from_rgb(40, s, s));
            draw_density_strip(ui, &self.density_pcie, 12.0, |s| egui::Color32::from_rgb(s, 40, s));
            // Value track (`--track`): the semantic value curve on the same axis as the ticks.
            if !self.track.is_empty() {
                draw_value_track(ui, &self.track, 28.0, &self.track_label);
            }
            ui.add_space(2.0);
            egui::ScrollArea::horizontal().show(ui, |ui| {
                ui.horizontal(|ui| {
                    for (i, c) in self.model.checkpoints.iter().enumerate() {
                        let [r, g, b] = type_color(c.kind);
                        let color = egui::Color32::from_rgb(r, g, b);
                        let sel = i == self.sel;
                        let size = egui::vec2(if sel { 16.0 } else { 10.0 }, 24.0);
                        let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::click());
                        ui.painter().rect_filled(rect, 2.0, color);
                        if sel {
                            ui.painter().rect_stroke(
                                rect,
                                2.0,
                                egui::Stroke::new(2.0, egui::Color32::WHITE),
                                egui::StrokeKind::Outside,
                            );
                        }
                        if resp.clicked() {
                            self.sel = i;
                        }
                        resp.on_hover_text(format!("#{} {:?} {}", c.id, c.kind, c.cause));
                    }
                });
            });
            ui.add_space(2.0);
        });

        // Left: checkpoint list.
        egui::Panel::left("checkpoints").default_size(280.0).show(ui, |ui| {
            ui.heading("Checkpoints");
            egui::ScrollArea::vertical().show(ui, |ui| {
                for i in 0..n {
                    let c = &self.model.checkpoints[i];
                    let [r, g, b] = type_color(c.kind);
                    let label = format!(
                        "#{:<3} {:>9.1}ms  {:?}  {}",
                        c.id,
                        c.ts_ns as f64 / 1e6,
                        c.kind,
                        c.cause
                    );
                    let mut text = egui::RichText::new(label).monospace();
                    if i == self.sel {
                        text = text.strong();
                    }
                    ui.horizontal(|ui| {
                        let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                        ui.painter().rect_filled(rect, 2.0, egui::Color32::from_rgb(r, g, b));
                        if ui.selectable_label(i == self.sel, text).clicked() {
                            self.sel = i;
                        }
                    });
                }
            });
        });

        // Right/centre: screenshot pane on top, inspector below.
        egui::CentralPanel::default().show(ui, |ui| {
            if let Some(c) = self.model.checkpoints.get(self.sel).cloned() {
                ui.horizontal(|ui| {
                    ui.strong(format!("Checkpoint #{}  {:?}", c.id, c.kind));
                    ui.label(format!("· {}", c.cause));
                    if let Some(p) = &c.fg_process {
                        ui.label(format!("· {p}"));
                    }
                });
                if let Some(w) = &c.fg_window {
                    ui.label(format!("window: {w}"));
                }
                if let Some(note) = &c.note {
                    ui.label(format!("note: {note}"));
                }
                ui.separator();

                let avail_h = ui.available_height();
                // Screenshot pane (top ~55%).
                egui::ScrollArea::both().max_height(avail_h * 0.55).id_salt("shot").show(ui, |ui| {
                    if let Some(tex) = &self.tex {
                        let size = tex.size_vec2();
                        let max_w = ui.available_width().max(64.0);
                        let scale = (max_w / size.x).min(1.0);
                        ui.add(egui::Image::new(tex).fit_to_exact_size(size * scale));
                        // Draw the cursor position marker.
                        // (kept simple: the cursor coords are shown textually)
                        ui.label(format!("cursor: ({}, {})", c.cursor.0, c.cursor.1));
                    } else if c.screenshot_id.is_some() {
                        ui.weak("(screenshot file missing)");
                    } else {
                        ui.weak("(no screenshot for this checkpoint)");
                    }
                });

                ui.separator();
                ui.strong(format!("Traffic around anchor (±{} frames)", self.window));
                egui::ScrollArea::vertical().id_salt("frames").show(ui, |ui| {
                    for row in &self.rows {
                        let anchored = c.anchor.map(|a| a.event_index) == Some(row.index);
                        let mut h = egui::RichText::new(&row.header).monospace();
                        if anchored {
                            h = h.strong().color(egui::Color32::from_rgb(66, 135, 245));
                        }
                        ui.label(h);
                        if !row.hex.is_empty() {
                            ui.label(egui::RichText::new(format!("    {}", row.hex)).monospace().weak());
                        }
                    }
                    if self.rows.is_empty() {
                        ui.weak("(no anchored traffic for this checkpoint)");
                    }
                });

                // Co-logged PCIe events anchored to this same checkpoint (both wires).
                if !self.secondary_rows.is_empty() {
                    ui.separator();
                    ui.strong("Co-logged PCIe at this checkpoint");
                    for row in &self.secondary_rows {
                        ui.label(
                            egui::RichText::new(&row.header)
                                .monospace()
                                .color(egui::Color32::from_rgb(181, 140, 208)),
                        );
                    }
                }
            } else {
                ui.centered_and_justified(|ui| ui.label("session has no checkpoints"));
            }
        });
    }
}
