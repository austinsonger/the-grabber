/**
 * ASCII wordmark, matching LOGO / LOGO_COLORS in src/tui/ui/theme.rs — cyan
 * on the top two rows, teal in the middle, purple on the bottom.
 */
const LINES = [
  " ██████╗ ██████╗  █████╗ ██████╗ ██████╗ ███████╗██████╗ ",
  "██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗",
  "██║  ███╗██████╔╝███████║██████╔╝██████╔╝█████╗  ██████╔╝",
  "██║   ██║██╔══██╗██╔══██║██╔══██╗██╔══██╗██╔══╝  ██╔══██╗",
  "╚██████╔╝██║  ██║██║  ██║██████╔╝██████╔╝███████╗██║  ██║",
  " ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝",
];

const CLASSES = ["", "", "logo-mid", "logo-mid", "logo-low", "logo-low"];

export default function Logo() {
  return (
    <pre className="grabber-logo" aria-label="The Grabber">
      {LINES.map((line, i) => (
        <div key={i} className={CLASSES[i]}>
          {line}
        </div>
      ))}
    </pre>
  );
}
