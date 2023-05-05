use eframe::egui;
use engine::RozmitmatApp;
use interfaces::RunSpoof;

mod engine;
mod extensions;
mod interfaces;
mod networkutils;
mod processutil;

const APP_NAME: &str = "Rozmitmat v0.1.0";
const FULL_APP_NAME: &str = "Rozmitmat - Rozen MITM Attack Tool";
const WINDOW_WIDTH: f32 = 600.0;
const WINDOW_HEIGHT: f32 = 400.0;

#[cfg(target_os = "windows")]
fn main() {
    panic!("This program is not supported on Windows.");
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(WINDOW_WIDTH, WINDOW_HEIGHT)),
        ..Default::default()
    };

    eframe::run_native(
        APP_NAME,
        options,
        Box::new(|_cc| Box::<RozmitmatApp>::default()),
    )
}

/// A main window GUI builder
impl eframe::App for RozmitmatApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading(FULL_APP_NAME);
            });

            let r = self.running.lock().unwrap();
            let rv = *r;
            drop(r);

            if !rv {
                ui.horizontal(|ui| {
                    ui.label("Interface name:");
                    ui.add(egui::TextEdit::singleline(&mut self.interface_name));
                });

                ui.horizontal(|ui| {
                    ui.label("Target IP:");
                    ui.add(egui::TextEdit::singleline(&mut self.target_ip));
                });

                ui.horizontal(|ui| {
                    ui.label("Router IP:");
                    ui.add(egui::TextEdit::singleline(&mut self.router_ip));
                });

                ui.checkbox(&mut self.verbose, "Verbose");

                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.proxy, "Proxy");
                    if self.proxy {
                        ui.label("Proxy port number:");
                        ui.add(egui::TextEdit::singleline(&mut self.proxy_port));
                    }
                });

                ui.separator();
                ui.checkbox(&mut self.is_dns_spoof_checked, "DNS Spoof");

                if self.is_dns_spoof_checked {
                    ui.horizontal(|ui| {
                        ui.label("Domain name:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.domain_name)
                                .hint_text("Domain name to spoof e.g. example.com"),
                        );
                    });

                    ui.horizontal(|ui| {
                        ui.label("Redirect to IP:");
                        ui.add(egui::TextEdit::singleline(&mut self.redirect_ip));
                    });
                }

                ui.separator();
            }

            if rv {
                ui.label("Running...");

                if ui.button("Stop").clicked() {
                    self.stop();
                }
            } else if ui.button("Start").clicked() {
                match self.check_input() {
                    Ok(_) => {
                        self.last_error = "".to_string();
                        self.output.lock().unwrap().clear();
                        self.start();
                    }
                    Err(err) => {
                        self.last_error = err;
                    }
                }
            }

            ui.vertical_centered(|ui| {
                ui.label(&self.last_error);
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::Window::new("Output")
                .resizable(true)
                .min_width(WINDOW_WIDTH - 10.0)
                .scroll2([false, true])
                .show(ui.ctx(), |ui| {
                    let str = self.output.lock().unwrap();
                    let txt = str.clone();
                    drop(str);
                    ui.add(
                        egui::TextEdit::multiline(&mut txt.as_str())
                            .font(egui::FontId::proportional(18.0))
                            .frame(false)
                            .desired_width(f32::INFINITY),
                    )
                    .context_menu(|ui| {
                        ui.menu_button("Actions", |ui| {
                            if ui.button("Save").clicked() {
                                if let Some(e) = self.save_log(&txt).err() {
                                    self.last_error = e.to_string();
                                }
                                ui.close_menu();
                            }

                            if ui.button("Clear").clicked() {
                                self.clear_output();
                                ui.close_menu();
                            }
                        });
                    });
                });
        });
    }
}
