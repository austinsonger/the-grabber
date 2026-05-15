use ratatui::style::Color;

// ═══════════════════════════════════════════════════════════════════════════
// Color palette — RGB true color
// ═══════════════════════════════════════════════════════════════════════════

// Background layers
pub(super) const BG_DARK: Color = Color::Rgb(15, 17, 26);
pub(super) const BG_MAIN: Color = Color::Rgb(24, 28, 39);
pub(super) const BG_ELEVATED: Color = Color::Rgb(35, 40, 55);
pub(super) const BG_SELECTED: Color = Color::Rgb(45, 52, 70);

// Primary accent — teal / sky
pub(super) const CYAN: Color = Color::Rgb(80, 200, 255);
pub(super) const CYAN_DIM: Color = Color::Rgb(40, 100, 140);

// Secondary accent — warm amber
pub(super) const AMBER: Color = Color::Rgb(255, 195, 55);

// Semantic
pub(super) const GREEN: Color = Color::Rgb(72, 213, 150);
pub(super) const RED: Color = Color::Rgb(245, 108, 108);
pub(super) const RED_BG: Color = Color::Rgb(60, 30, 30);
pub(super) const PURPLE: Color = Color::Rgb(160, 140, 245);
pub(super) const TEAL: Color = Color::Rgb(50, 180, 200);

// Text hierarchy
pub(super) const TEXT_BRIGHT: Color = Color::Rgb(234, 238, 245);
pub(super) const TEXT_NORMAL: Color = Color::Rgb(169, 177, 190);
pub(super) const TEXT_DIM: Color = Color::Rgb(90, 98, 112);

// Borders
pub(super) const BORDER_SUBTLE: Color = Color::Rgb(50, 56, 72);

// ═══════════════════════════════════════════════════════════════════════════
// Logo
// ═══════════════════════════════════════════════════════════════════════════

pub(super) const LOGO: &[&str] = &[
    r" ██████╗ ██████╗  █████╗ ██████╗ ██████╗ ███████╗██████╗ ",
    r"██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗",
    r"██║  ███╗██████╔╝███████║██████╔╝██████╔╝█████╗  ██████╔╝",
    r"██║   ██║██╔══██╗██╔══██║██╔══██╗██╔══██╗██╔══╝  ██╔══██╗",
    r"╚██████╔╝██║  ██║██║  ██║██████╔╝██████╔╝███████╗██║  ██║",
    r" ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝",
];

pub(super) const LOGO_COLORS: &[Color] = &[CYAN, CYAN, TEAL, TEAL, PURPLE, PURPLE];

// ═══════════════════════════════════════════════════════════════════════════
// Spinner
// ═══════════════════════════════════════════════════════════════════════════

pub(super) const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
