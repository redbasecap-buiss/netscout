use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph},
};
use std::io::stdout;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup terminal
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    // Main loop
    loop {
        terminal.draw(|frame| {
            let area = frame.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(0),
                    Constraint::Length(3),
                ])
                .split(area);

            // Title
            let title = Paragraph::new("🔍 netscout — Network Diagnostic Dashboard")
                .style(Style::default().fg(Color::Cyan).bold())
                .block(Block::default().borders(Borders::ALL));
            frame.render_widget(title, chunks[0]);

            // Main content
            let items = vec![
                ListItem::new("  [1] Ping"),
                ListItem::new("  [2] DNS Lookup"),
                ListItem::new("  [3] Port Scan"),
                ListItem::new("  [4] Traceroute"),
                ListItem::new("  [5] HTTP Probe"),
                ListItem::new("  [6] TLS Certificate"),
                ListItem::new("  [7] Speed Test"),
                ListItem::new("  [8] WHOIS"),
                ListItem::new("  [9] LAN Scan"),
            ];
            let list = List::new(items)
                .block(Block::default().title(" Tools ").borders(Borders::ALL))
                .style(Style::default().fg(Color::White));
            frame.render_widget(list, chunks[1]);

            // Status bar
            let status = Paragraph::new("Press 'q' to quit | Select a tool by number")
                .style(Style::default().fg(Color::DarkGray))
                .block(Block::default().borders(Borders::ALL));
            frame.render_widget(status, chunks[2]);
        })?;

        // Handle input
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}
