use eframe::egui;
use engine::RozmitmatApp;
use interfaces::RunSpoof;

mod networkutils;
mod engine;
mod interfaces;
mod extensions;

const APP_NAME: &str = "Rozmitmat v0.1.0";
const FULL_APP_NAME: &str = "Rozmitmat - Rozen MITM Attack Tool";
const WINDOW_WIDTH: f32 = 800.0;
const WINDOW_HEIGHT: f32 = 600.0;

fn main() -> Result<(), eframe::Error>
{   
    let options = eframe::NativeOptions 
    {
        initial_window_size: Some(egui::vec2(WINDOW_WIDTH, WINDOW_HEIGHT)),
        ..Default::default()
    };

    eframe::run_native(
        APP_NAME,
        options,
        Box::new(|_cc| Box::<RozmitmatApp>::default()),
    )
}

impl eframe::App for RozmitmatApp
{
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) 
    {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| 
        {
            ui.vertical_centered(|ui| 
            {
                ui.heading(FULL_APP_NAME);
            });

            ui.horizontal(|ui| 
            {
                ui.label("Interface name:");
                ui.add(egui::TextEdit::singleline(&mut self.interface_name));
            });

            ui.horizontal(|ui| 
            {
                ui.label("Target IP:");
                ui.add(egui::TextEdit::singleline(&mut self.target_ip));
            });

            ui.horizontal(|ui| 
            {
                ui.label("Router IP:");
                ui.add(egui::TextEdit::singleline(&mut self.router_ip));
            });

            ui.separator();
            ui.checkbox(&mut self.is_dns_spoof_checked, "DNS Spoof");

            if self.is_dns_spoof_checked
            {
                ui.horizontal(|ui| 
                {
                    ui.label("Domain name:");
                    ui.add(egui::TextEdit::singleline(&mut self.domain_name).hint_text("Domain name to spoof e.g. example.com"));
                });
    
                ui.horizontal(|ui| 
                {
                    ui.label("Redirect to IP:");
                    ui.add(egui::TextEdit::singleline(&mut self.redirect_ip));
                });        
            }

            ui.separator();

            if self.running
            {
                ui.label("Running...");

                if ui.button("Stop").clicked()
                {
                    self.stop();
                }    
            }
            else if ui.button("Start").clicked()
            {
                match self.check_input()
                {
                    Ok(_) => 
                    {
                        self.start();
                    },
                    Err(err) => 
                    {
                        self.last_error = err;
                    }
                }
            }

            ui.label(&self.last_error);
        });

        egui::CentralPanel::default().show(ctx, |ui| 
        {
            egui::Window::new("Output").resizable(true).scroll2([false, true]).min_width(400.0).show(ui.ctx(), |ui|
            {
                let str = self.output.lock().unwrap();
                let txt = str.clone();
                ui.add(egui::TextEdit::multiline(&mut txt.as_str()));
            });
        });
    }
}
