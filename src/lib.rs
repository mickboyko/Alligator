use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    pub stream_id: &'static str,
    pub room_id: &'static str,
    pub room_title: &'static str,
    pub author: &'static str,
    pub body: String,
}

impl Message {
    pub fn room_key(&self) -> String {
        format!("{}:{}", self.source.as_str(), self.room_id)
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
    stream_id: &'static str,
    room_id: &'static str,
    room_title: &'static str,
    author: &'static str,
    messages: Vec<&'static str>,
    min_interval: Duration,
    max_interval: Duration,
}

impl MockBridge {
    pub fn new(
        source: Source,
        stream_id: &'static str,
        room_id: &'static str,
        room_title: &'static str,
        author: &'static str,
        messages: Vec<&'static str>,
        min_interval: Duration,
        max_interval: Duration,
    ) -> Self {
        Self {
            source,
            stream_id,
            room_id,
            room_title,
            author,
            messages,
            min_interval,
            max_interval,
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
                            stream_id: self.stream_id,
                            room_id: self.room_id,
                            room_title: self.room_title,
                            author: self.author,
                            body: (*body).to_string(),
                        })
                        .is_err()
                    {
                        return;
                    }
                    let sleep_duration = if self.max_interval > self.min_interval {
                        let jitter_window_ms =
                            (self.max_interval - self.min_interval).as_millis() as u64;
                        let jitter_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|duration| duration.as_nanos() as u64 % (jitter_window_ms + 1))
                            .unwrap_or(0);
                        self.min_interval + Duration::from_millis(jitter_ms)
                    } else {
                        self.min_interval
                    };
                    thread::sleep(sleep_duration);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_message(
        source: Source,
        stream_id: &'static str,
        room_id: &'static str,
        body: &str,
    ) -> Message {
        Message {
            source,
            stream_id,
            room_id,
            room_title: "Engineering",
            author: "bot",
            body: body.to_string(),
        }
    }

    #[test]
    fn keeps_latest_preview_for_room() {
        let mut timeline = UnifiedTimeline::new();
        timeline.ingest(sample_message(Source::Slack, "stream-a", "eng", "first"));
        timeline.ingest(sample_message(Source::Slack, "stream-a", "eng", "second"));

        let rooms = timeline.ordered_rooms();
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0].preview, "second");
        assert_eq!(rooms[0].messages.len(), 2);
    }

    #[test]
    fn moves_recent_room_to_front() {
        let mut timeline = UnifiedTimeline::new();
        timeline.ingest(sample_message(Source::Slack, "stream-a", "eng", "slack"));
        timeline.ingest(sample_message(Source::Teams, "stream-b", "sales", "teams"));
        timeline.ingest(sample_message(
            Source::Slack,
            "stream-a",
            "eng",
            "slack again",
        ));

        let ordered = timeline.ordered_rooms();
        assert_eq!(ordered[0].source, Source::Slack);
        assert_eq!(ordered[1].source, Source::Teams);
    }

    #[test]
    fn keeps_single_room_entry_across_streams() {
        let mut timeline = UnifiedTimeline::new();
        timeline.ingest(sample_message(Source::Teams, "account-a", "ops", "from account a"));
        timeline.ingest(sample_message(Source::Teams, "account-b", "ops", "from account b"));

        let rooms = timeline.ordered_rooms();
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0].preview, "from account b");
        assert_eq!(rooms[0].messages.len(), 2);
    }

    #[test]
    fn keeps_sources_separate_for_same_room_id() {
        let mut timeline = UnifiedTimeline::new();
        timeline.ingest(sample_message(Source::Slack, "stream-a", "eng", "slack msg"));
        timeline.ingest(sample_message(Source::Teams, "stream-b", "eng", "teams msg"));

        let rooms = timeline.ordered_rooms();
        assert_eq!(rooms.len(), 2);
        assert_eq!(rooms[0].source, Source::Teams);
        assert_eq!(rooms[1].source, Source::Slack);
    }
}
