//! Read-only diagnostics for the production ingestion failure-notification
//! chain. A confirmed SNS subscription and valid CloudWatch alarm actions
//! are NOT proof that an alarm email was delivered.

use aws_sdk_cloudwatch::{types::MetricAlarm, Client as CloudWatchClient};
use aws_sdk_sns::{types::Subscription, Client as SnsClient};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertState {
    Ready,
    ActionRequired,
    UnableToCheck,
}

pub struct AlertChecks {
    pub subscription: AlertState,
    pub subscription_detail: &'static str,
    pub alarms: AlertState,
    pub alarms_detail: &'static str,
}

#[derive(Clone)]
pub struct AlertInspector {
    sns: SnsClient,
    cloudwatch: CloudWatchClient,
    topic_arn: String,
    notification_email: String,
    alarm_names: Vec<String>,
}

impl AlertInspector {
    pub fn new(
        sns: SnsClient,
        cloudwatch: CloudWatchClient,
        topic_arn: String,
        notification_email: String,
        alarm_names: Vec<String>,
    ) -> Self {
        Self {
            sns,
            cloudwatch,
            topic_arn,
            notification_email,
            alarm_names,
        }
    }

    pub async fn inspect(&self) -> AlertChecks {
        let subscription = self.inspect_subscription().await;
        let alarms = self.inspect_alarms().await;
        AlertChecks {
            subscription,
            subscription_detail: match subscription {
                AlertState::Ready => "The configured failure-notification email subscription is confirmed in SNS. Mailbox delivery is not tested.",
                AlertState::ActionRequired => "No confirmed SNS email subscription matches the configured notification address. Accept the confirmation message.",
                AlertState::UnableToCheck => "Unable to inspect SNS subscriptions. Check the configured topic and read permissions.",
            },
            alarms,
            alarms_detail: match alarms {
                AlertState::Ready => "All four expected CloudWatch failure alarms are configured with enabled actions to the intended SNS topic. Delivery has not been tested.",
                AlertState::ActionRequired => "An expected CloudWatch failure alarm is missing, disabled, or not wired to the configured SNS topic.",
                AlertState::UnableToCheck => "Unable to inspect the expected CloudWatch alarms. Check read permissions and stack outputs.",
            },
        }
    }

    async fn inspect_subscription(&self) -> AlertState {
        // Read only this configured topic, never enumerate all account SNS
        // subscriptions. Cap pagination to avoid unbounded request work.
        let mut next = None;
        for _ in 0..5 {
            let result = self
                .sns
                .list_subscriptions_by_topic()
                .topic_arn(&self.topic_arn)
                .set_next_token(next)
                .send()
                .await;
            let Ok(page) = result else {
                return AlertState::UnableToCheck;
            };
            if has_confirmed_subscription(page.subscriptions(), &self.notification_email) {
                return AlertState::Ready;
            }
            next = page.next_token().map(str::to_owned);
            if next.is_none() {
                return AlertState::ActionRequired;
            }
        }
        AlertState::UnableToCheck
    }

    async fn inspect_alarms(&self) -> AlertState {
        let result = self
            .cloudwatch
            .describe_alarms()
            .set_alarm_names(Some(self.alarm_names.clone()))
            .send()
            .await;
        let Ok(page) = result else {
            return AlertState::UnableToCheck;
        };
        if page.next_token().is_some() {
            return AlertState::UnableToCheck;
        }
        if alarms_wired(page.metric_alarms(), &self.alarm_names, &self.topic_arn) {
            AlertState::Ready
        } else {
            AlertState::ActionRequired
        }
    }
}

fn has_confirmed_subscription(subscriptions: &[Subscription], recipient: &str) -> bool {
    subscriptions.iter().any(|item| {
        item.protocol() == Some("email")
            && item
                .endpoint()
                .is_some_and(|email| email.eq_ignore_ascii_case(recipient))
            && item
                .subscription_arn()
                .is_some_and(|arn| arn.starts_with("arn:"))
    })
}

fn alarms_wired(alarms: &[MetricAlarm], expected: &[String], topic_arn: &str) -> bool {
    expected.len() == 4
        && expected.iter().all(|name| {
            alarms.iter().any(|alarm| {
                alarm.alarm_name() == Some(name.as_str())
                    && alarm.actions_enabled() == Some(true)
                    && alarm
                        .alarm_actions()
                        .iter()
                        .any(|action| action == topic_arn)
            })
        })
}

#[cfg(test)]
mod tests {
    use super::{alarms_wired, has_confirmed_subscription};
    use aws_sdk_cloudwatch::types::MetricAlarm;
    use aws_sdk_sns::types::Subscription;

    #[test]
    fn subscription_must_be_confirmed_for_exact_email() {
        let pending = Subscription::builder()
            .protocol("email")
            .endpoint("alerts@example.test")
            .subscription_arn("PendingConfirmation")
            .build();
        let confirmed = Subscription::builder()
            .protocol("email")
            .endpoint("alerts@example.test")
            .subscription_arn("arn:aws:sns:region:123:topic:sub")
            .build();
        assert!(!has_confirmed_subscription(
            &[pending],
            "alerts@example.test"
        ));
        assert!(has_confirmed_subscription(
            &[confirmed],
            "alerts@example.test"
        ));
    }

    #[test]
    fn four_enabled_metric_alarms_must_send_to_topic() {
        let topic = "arn:aws:sns:region:123:topic";
        let names: Vec<String> = (0..4).map(|i| format!("stack-Alarm{i}")).collect();
        let alarms: Vec<_> = names
            .iter()
            .map(|name| {
                MetricAlarm::builder()
                    .alarm_name(name)
                    .actions_enabled(true)
                    .alarm_actions(topic)
                    .build()
            })
            .collect();
        assert!(alarms_wired(&alarms, &names, topic));
        assert!(!alarms_wired(&alarms[..3], &names, topic));
        assert!(!alarms_wired(&alarms, &names, "arn:other"));
    }
}
