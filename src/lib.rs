pub mod auth;
pub mod providers;
pub mod vault;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use providers::CredentialProvider;

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

    pub fn provider_key(self) -> &'static str {
        match self {
            Source::Teams => "teams",
            Source::GoogleChat => "google-chat",
            Source::Slack => "slack",
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
    fn start(self, sender: Sender<Message>, credentials: Arc<dyn CredentialProvider>);
}

pub struct MockBridge {
    source: Source,
    stream_id: &'static str,
    room_id: &'static str,
    room_title: &'static str,
    author: &'static str,
    messages: Vec<&'static str>,
    interval: Duration,
}

impl MockBridge {
    pub fn new(
        source: Source,
        stream_id: &'static str,
        room_id: &'static str,
        room_title: &'static str,
        author: &'static str,
        messages: Vec<&'static str>,
        interval: Duration,
    ) -> Self {
        Self {
            source,
            stream_id,
            room_id,
            room_title,
            author,
            messages,
            interval,
        }
    }
}

impl Bridge for MockBridge {
    fn start(self, sender: Sender<Message>, credentials: Arc<dyn CredentialProvider>) {
        thread::spawn(move || {
            loop {
                for body in &self.messages {
                    if credentials.access_token_for_source(self.source).is_none() {
                        thread::sleep(self.interval);
                        continue;
                    }

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
                    thread::sleep(self.interval);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::mpsc;

    use super::*;
    use crate::providers::SessionCredentialProvider;
    use crate::vault::Vault;

    fn temp_path(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "alligator-lib-{label}-{}.json",
            rand::random::<u64>()
        ));
        path
    }

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
        timeline.ingest(sample_message(
            Source::Teams,
            "account-a",
            "ops",
            "from account a",
        ));
        timeline.ingest(sample_message(
            Source::Teams,
            "account-b",
            "ops",
            "from account b",
        ));

        let rooms = timeline.ordered_rooms();
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0].preview, "from account b");
        assert_eq!(rooms[0].messages.len(), 2);
    }

    #[test]
    fn keeps_sources_separate_for_same_room_id() {
        let mut timeline = UnifiedTimeline::new();
        timeline.ingest(sample_message(
            Source::Slack,
            "stream-a",
            "eng",
            "slack msg",
        ));
        timeline.ingest(sample_message(
            Source::Teams,
            "stream-b",
            "eng",
            "teams msg",
        ));

        let rooms = timeline.ordered_rooms();
        assert_eq!(rooms.len(), 2);
        assert_eq!(rooms[0].source, Source::Teams);
        assert_eq!(rooms[1].source, Source::Slack);
    }

    #[test]
    fn mock_bridge_requires_credentials() {
        let password = format!("password-{}", rand::random::<u64>());
        let (tx, rx) = mpsc::channel();
        let path = temp_path("bridge");
        let vault = Vault::create(&path, Some(password.as_str()), &[]).expect("create vault");
        let mut unlocked = vault
            .unlock_with_password(password.as_str())
            .expect("unlock");
        unlocked.upsert_token(
            "slack",
            vec!["chat:read".to_string()],
            Some(100),
            "access",
            "refresh",
        );
        let credentials = Arc::new(SessionCredentialProvider::from_unlocked(&unlocked));

        MockBridge::new(
            Source::Slack,
            "stream",
            "room",
            "Room",
            "bot",
            vec!["hello"],
            Duration::from_millis(5),
        )
        .start(tx, credentials);

        let message = rx
            .recv_timeout(Duration::from_millis(100))
            .expect("message should be emitted when credentials are present");
        assert_eq!(message.body, "hello");
    }
}
