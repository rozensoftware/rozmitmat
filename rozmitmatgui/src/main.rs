use eframe::egui;

const APP_NAME: &str = "Rozmitmat v0.1.0";
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

struct RozmitmatApp
{
    console_output: String,
}

impl Default for RozmitmatApp
{
    fn default() -> Self 
    {
        Self 
        {
            console_output: "shdgshdsdsdggggggggggggggggg".to_string(),
        }
    }
}

impl eframe::App for RozmitmatApp
{
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) 
    {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| 
        {
            ui.heading(APP_NAME);
            //render label centered in the panel
            ui.horizontal(|ui| 
            {
                ui.centered_and_justified(|ui| 
                {
                    ui.label("Rozmitmat");
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| 
        {
            egui::Window::new("Console").resizable(true).scroll2([false, true]).show(ui.ctx(), |ui|
            {
                let mut txt = self.console_output.as_str();
                let console_txt = egui::TextEdit::multiline(&mut txt);//.min_size(egui::vec2(100.0, 100.0));
                ui.add(console_txt);
            });
        });

        // egui::CentralPanel::default().show(ctx, |ui| {
        //     ui.heading("My egui Application");
        //     ui.horizontal(|ui| {
        //         let name_label = ui.label("Your name: ");
        //         ui.text_edit_singleline(&mut self.name)
        //             .labelled_by(name_label.id);
        //     });
            
        //     ui.add(egui::Slider::new(&mut self.age, 0..=120).text("age"));
            
        //     if ui.button("Click each year").clicked() 
        //     {
        //         self.age += 1;
        //     }
            
        //     ui.label(format!("Hello '{}', age {}", self.name, self.age));
        // });
    }
}
