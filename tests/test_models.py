from __future__ import annotations

import pytest
from pydantic import ValidationError

from mems_mcp.models import (
    BatchStatusItem,
    BroadcastBatchOptions,
    BroadcastEndpoint,
    MessageChannel,
    PushNotificationContent,
    RcsContent,
    SendBroadcastRequest,
    SendMessageRequest,
    VoiceContent,
    WhatsAppContent,
)


def test_send_message_request_builds_expected_payload() -> None:
    request = SendMessageRequest(channel=MessageChannel.SMS, destination="61299002200", text="Hello")
    assert request.to_payload() == {"messageType": "sms", "destination": "61299002200", "text": "Hello"}


def test_send_message_request_requires_text_or_template() -> None:
    with pytest.raises(ValidationError, match="Either 'text', 'template_name'"):
        SendMessageRequest(channel=MessageChannel.SMS, destination="61299002200")


def test_send_message_request_enforces_sms_length_limit() -> None:
    with pytest.raises(ValidationError, match="1400 character limit"):
        SendMessageRequest(channel=MessageChannel.SMS, destination="61299002200", text="a" * 1401)


def test_send_message_request_enforces_max_destinations() -> None:
    destinations = ",".join(f"612990022{n:02d}" for n in range(251))
    with pytest.raises(ValidationError, match="maximum of 250"):
        SendMessageRequest(channel=MessageChannel.SMS, destination=destinations, text="Hello")


def test_send_message_request_validates_reply_to_ton() -> None:
    with pytest.raises(ValidationError, match="reply_to_ton"):
        SendMessageRequest(channel=MessageChannel.SMS, destination="61299002200", text="Hello", reply_to_ton=99)


def test_send_message_request_includes_optional_fields_only_when_set() -> None:
    request = SendMessageRequest(
        channel=MessageChannel.SMS,
        destination="61299002200",
        text="Hello",
        client_message_id="ABC-3-123",
        source="61412123456",
    )
    payload = request.to_payload()
    assert payload["clientMessageId"] == "ABC-3-123"
    assert payload["source"] == "61412123456"
    assert "templateName" not in payload


def test_send_message_request_merges_extra_for_rich_channel_content() -> None:
    request = SendMessageRequest(
        channel=MessageChannel.RCS,
        destination="61299002200",
        text="Hello",
        extra={"rcs": {"suggestions": [{"text": "Yes", "postbackData": "yes123"}]}},
    )
    payload = request.to_payload()
    assert payload["rcs"] == {"suggestions": [{"text": "Yes", "postbackData": "yes123"}]}


def test_batch_status_item_payload() -> None:
    item = BatchStatusItem(id=2148226149, message_type="SMS")
    assert item.to_payload() == {"id": 2148226149, "messageType": "SMS"}


def test_send_broadcast_request_builds_expected_payload() -> None:
    request = SendBroadcastRequest(
        text="Hello Broadcast",
        endpoints=[BroadcastEndpoint(type=1, id=211232)],
    )
    assert request.to_payload() == {
        "message": {"text": "Hello Broadcast"},
        "endpoints": [{"type": 1, "id": 211232}],
    }


def test_send_broadcast_request_includes_batch_options() -> None:
    request = SendBroadcastRequest(
        text="Hello Broadcast",
        endpoints=[BroadcastEndpoint(type=1, id=211232)],
        registered=True,
        batch_options=BroadcastBatchOptions(batch_size=100, sleep_duration=5),
    )
    payload = request.to_payload()
    assert payload["registered"] == "true"
    assert payload["batchOptions"] == {"batchSize": 100, "sleepDuration": 5}


# --- RCS rich content -------------------------------------------------------


def test_rcs_content_requires_exactly_one_of_text_media_rich_card() -> None:
    with pytest.raises(ValidationError, match="exactly one"):
        RcsContent(text="hi", media={"file_url": "https://example.com/image.jpg"})


def test_rcs_content_rejects_too_many_suggestions() -> None:
    suggestions = [{"text": f"Option {i}", "postback_data": f"id{i}"} for i in range(12)]
    with pytest.raises(ValidationError, match="maximum of 11"):
        RcsContent(text="hi", suggestions=suggestions)


def test_send_message_request_serializes_rcs_rich_card() -> None:
    request = SendMessageRequest(
        channel=MessageChannel.RCS,
        destination="61299002200",
        rcs={
            "rich_card": {
                "cards": [
                    {
                        "title": "Card Title",
                        "media": {"file_url": "https://example.com/card.jpg", "height": "SHORT"},
                        "suggestions": [{"text": "View", "postback_data": "view123"}],
                    }
                ]
            }
        },
    )
    payload = request.to_payload()
    assert payload["rcs"] == {
        "richCard": {
            "cards": [
                {
                    "title": "Card Title",
                    "media": {"fileUrl": "https://example.com/card.jpg", "height": "SHORT"},
                    "suggestions": [{"text": "View", "postbackData": "view123"}],
                }
            ]
        }
    }
    # rcs content is a valid substitute for text/templateName
    assert "text" not in payload and "templateName" not in payload


def test_rcs_content_with_dial_action_suggestion() -> None:
    content = RcsContent(
        text="Hello!",
        suggestions=[
            {"text": "Call Us", "postback_data": "call_123", "dial_action": {"phone_number": "+61299002200"}}
        ],
    )
    assert content.to_payload() == {
        "text": "Hello!",
        "suggestions": [{"text": "Call Us", "postbackData": "call_123", "dialAction": {"phoneNumber": "+61299002200"}}],
    }


# --- WhatsApp rich content ---------------------------------------------------


def test_whatsapp_content_image_message() -> None:
    content = WhatsAppContent(type="image", image={"url": "https://example.com/pic.jpg", "caption": "A pic"})
    assert content.to_payload() == {"type": "image", "image": {"url": "https://example.com/pic.jpg", "caption": "A pic"}}


def test_whatsapp_content_text_message_keeps_snake_case_preview_url() -> None:
    content = WhatsAppContent(type="text", text={"body": "hi", "preview_url": True})
    payload = content.to_payload()
    assert payload == {"type": "text", "text": {"body": "hi", "preview_url": True}}


def test_whatsapp_content_interactive_button_message() -> None:
    content = WhatsAppContent(
        type="interactive",
        interactive={
            "type": "button",
            "body": {"text": "how are you?"},
            "action": {"buttons": [{"title": "Good", "postback_data": "good123"}]},
        },
    )
    payload = content.to_payload()
    assert payload["interactive"]["action"]["buttons"] == [
        {"type": "reply", "title": "Good", "postbackData": "good123"}
    ]


def test_whatsapp_content_template_message() -> None:
    content = WhatsAppContent(
        type="template",
        template={"name": "New_Template", "language": "es", "body": {"parameters": ["SampleValue"]}},
    )
    payload = content.to_payload()
    assert payload == {
        "type": "template",
        "template": {"name": "New_Template", "language": "es", "body": {"parameters": ["SampleValue"]}},
    }


def test_send_message_request_allows_whatsapp_content_without_text() -> None:
    request = SendMessageRequest(
        channel=MessageChannel.WHATSAPP,
        destination="61299002200",
        whatsapp={"type": "location", "location": {"longitude": 151.2, "latitude": -33.8}},
    )
    payload = request.to_payload()
    assert payload["whatsapp"] == {"type": "location", "location": {"longitude": 151.2, "latitude": -33.8}}


# --- Voice rich content -------------------------------------------------------


def test_voice_content_text2voice_serializes_camel_case() -> None:
    content = VoiceContent(
        text2voice={
            "before_password_text": "Your password is",
            "password": "HelloPa55word",
            "password_spoken_speed": 1,
            "loop": 2,
            "gender": 2,
            "language": "en-AU",
            "spoken_speed": 0,
        }
    )
    payload = content.to_payload()
    assert payload["text2voice"]["beforePasswordText"] == "Your password is"
    assert payload["text2voice"]["passwordSpokenSpeed"] == 1
    assert payload["text2voice"]["language"] == "en-AU"


def test_voice_content_rejects_out_of_range_gender() -> None:
    with pytest.raises(ValidationError):
        VoiceContent(text2voice={"gender": 3})


# --- Push notification content ------------------------------------------------


def test_push_notification_content_serializes() -> None:
    content = PushNotificationContent(notification={"title": "Sample title", "body": "Sample body"})
    assert content.to_payload() == {"notification": {"title": "Sample title", "body": "Sample body"}}


def test_send_message_request_uses_push_notification_camel_case_key() -> None:
    request = SendMessageRequest(
        channel=MessageChannel.PUSHNOTIFICATION,
        destination="device-id-123",
        push_notification={"notification": {"title": "Hi", "body": "There"}},
    )
    payload = request.to_payload()
    assert payload["pushNotification"] == {"notification": {"title": "Hi", "body": "There"}}
