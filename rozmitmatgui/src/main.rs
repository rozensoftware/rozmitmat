use eframe::egui;
use memmap2::MmapMut;

mod networkutils;

const APP_NAME: &str = "Rozmitmat v0.1.0";
const WINDOW_WIDTH: f32 = 800.0;
const WINDOW_HEIGHT: f32 = 600.0;
const MEMORY_MAP_FILE_NAME: &str = "output.mmap";
const MEMORY_FILE_SIZE: usize = 1024 * 1024 * 5; // 5 MB

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
    interface_name: String,
    target_ip: String,
    domain_name: String,
    router_ip: String,
    redirect_ip: String,
    memoryfile: MmapMut,
}

impl Default for RozmitmatApp
{
    fn default() -> Self 
    {
        let ret = match networkutils::get_router_ip()
        {
            Ok(ip) => ip,
            Err(_) => 
            {
                (String::new(), String::new())
            }
        };

        let mem_mapped_file_name = std::env::current_exe().unwrap().parent().unwrap().to_str().unwrap().to_string() + "/" + MEMORY_MAP_FILE_NAME;

        let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(mem_mapped_file_name).unwrap();

        file.set_len(MEMORY_FILE_SIZE as u64).unwrap();

        let mut memoryfile = unsafe { MmapMut::map_mut(&file).unwrap() };
        memoryfile[0] = 0;

        Self 
        {
            console_output: String::new(),
            interface_name: ret.1,
            target_ip: String::new(),
            domain_name: String::new(),   
            router_ip: ret.0,
            redirect_ip: String::new(),
            memoryfile: memoryfile,
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
        });

        egui::CentralPanel::default().show(ctx, |ui| 
        {
            egui::Window::new("Output").resizable(true).scroll2([false, true]).show(ui.ctx(), |ui|
            {
                if self.memoryfile[0] != 0
                {
                    self.console_output = String::from_utf8_lossy(&self.memoryfile).to_string();
                }
                else
                {
                    self.console_output = String::new();
                }

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
