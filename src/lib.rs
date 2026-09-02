use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Source {
    Teams,
    GoogleChat,
    Slack,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Teams => "Teams",
            Source::GoogleChat => "Google Chat",
            Source::Slack => "Slack",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    pub source: Source,
    pub room_id: &'static str,
    pub room_title: &'static str,
    pub author: &'static str,
    pub body: String,
}

impl Message {
    pub fn room_key(&self) -> String {
        self.room_id.to_string()
    }
}

#[derive(Debug, Clone)]
pub struct Room {
    pub source: Source,
    pub title: String,
    pub preview: String,
    pub messages: Vec<Message>,
}

impl Room {
    fn new(message: Message) -> Self {
        Self {
            source: message.source,
            title: message.room_title.to_string(),
            preview: message.body.clone(),
            messages: vec![message],
        }
    }
}

#[derive(Default)]
pub struct UnifiedTimeline {
    rooms: HashMap<String, Room>,
    ordered_room_keys: Vec<String>,
}

impl UnifiedTimeline {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ingest(&mut self, message: Message) {
        let key = message.room_key();

        if let Some(room) = self.rooms.get_mut(&key) {
            room.source = message.source;
            room.title = message.room_title.to_string();
            room.preview = message.body.clone();
            room.messages.push(message);
        } else {
            self.rooms.insert(key.clone(), Room::new(message));
        }

        self.ordered_room_keys.retain(|existing| existing != &key);
        self.ordered_room_keys.insert(0, key);
    }

    pub fn ordered_rooms(&self) -> Vec<&Room> {
        self.ordered_room_keys
            .iter()
            .filter_map(|key| self.rooms.get(key))
            .collect()
    }
}

pub trait Bridge: Send + 'static {
    fn start(self, sender: Sender<Message>);
}

pub struct MockBridge {
    source: Source,
    room_id: &'static str,
    room_title: &'static str,
    author: &'static str,
    messages: Vec<&'static str>,
    interval: Duration,
}

impl MockBridge {
    pub fn new(
        source: Source,
        room_id: &'static str,
        room_title: &'static str,
        author: &'static str,
        messages: Vec<&'static str>,
        interval: Duration,
    ) -> Self {
        Self {
            source,
            room_id,
            room_title,
            author,
            messages,
            interval,
        }
    }
}

impl Bridge for MockBridge {
    fn start(self, sender: Sender<Message>) {
        thread::spawn(move || {
            loop {
                for body in &self.messages {
                    if sender
                        .send(Message {
                            source: self.source,
                            room_id: self.room_id,
                            room_title: self.room_title,
                            author: self.author,
                            body: (*body).to_string(),
                        })
                        .is_err()
                    {
                        return;
                    }
                    thread::sleep(self.interval);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_message(source: Source, room_id: &'static str, body: &str) -> Message {
        Message {
            source,
            room_id,
            room_title: "Engineering",
            author: "bot",
            body: body.to_string(),
        }
    }

    #[test]
    fn keeps_latest_preview_for_room() {
        let mut timeline = UnifiedTimeline::new();
        timeline.ingest(sample_message(Source::Slack, "eng", "first"));
        timeline.ingest(sample_message(Source::Slack, "eng", "second"));

        let rooms = timeline.ordered_rooms();
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0].preview, "second");
        assert_eq!(rooms[0].messages.len(), 2);
    }

    #[test]
    fn moves_recent_room_to_front() {
        let mut timeline = UnifiedTimeline::new();
        timeline.ingest(sample_message(Source::Slack, "eng", "slack"));
        timeline.ingest(sample_message(Source::Teams, "sales", "teams"));
        timeline.ingest(sample_message(Source::Slack, "eng", "slack again"));

        let ordered = timeline.ordered_rooms();
        assert_eq!(ordered[0].source, Source::Slack);
        assert_eq!(ordered[1].source, Source::Teams);
    }

    #[test]
    fn keeps_shared_room_ungrouped_across_sources() {
        let mut timeline = UnifiedTimeline::new();
        timeline.ingest(sample_message(Source::Slack, "eng", "slack msg"));
        timeline.ingest(sample_message(Source::Teams, "eng", "teams msg"));

        let rooms = timeline.ordered_rooms();
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0].preview, "teams msg");
        assert_eq!(rooms[0].messages.len(), 2);
    }
}
