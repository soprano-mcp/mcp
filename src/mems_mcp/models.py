"""Pydantic models mirroring the Connect API's Payload Parameters (see the
"Payload Parameters" section of docs/CONNECT API - Developer Guide.pdf).

Common real-time-mode fields are fully modeled and validated. Channel-specific
rich content is modeled per-channel where the guide documents a concrete JSON
schema (RCS `rcs`, WhatsApp `whatsapp`, Voice `voice`, `pushNotification`) -
see the per-model docstrings below for the exact guide section each mirrors.
Viber's rich content isn't documented in this guide at all (it points to a
separate channel-specific guide) - for that, and for any field not otherwise
covered, use `extra` on `SendMessageRequest`, which is merged into the
outgoing JSON payload verbatim.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic.alias_generators import to_camel

MAX_TEXT_LENGTH: dict[str, int] = {
    "sms": 1400,
    "rcs": 4000,
    "whatsapp": 4000,
    "email": 10000,
    "viber": 4000,
}

MAX_REALTIME_DESTINATIONS = 250
VALID_REPLY_TO_TON = {0, 1, 3, 8, 10, 12}
MAX_RCS_SUGGESTIONS = 11


class _CamelModel(BaseModel):
    """Base for rich-content sub-models: auto camelCase aliasing.

    The Connect API's rich-content objects (RCS, WhatsApp, Voice, Push) use
    camelCase JSON keys (`postbackData`, `cardOrientation`, ...). Fields are
    defined here in snake_case (Python convention) and aliased to camelCase
    automatically; `populate_by_name=True` also accepts the snake_case name or
    the camelCase alias on input, and `.model_dump(by_alias=True)` emits the
    camelCase key expected by the Connect API.
    """

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    def to_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class MessageChannel(str, Enum):
    SMS = "sms"
    WHATSAPP = "whatsapp"
    RCS = "rcs"
    EMAIL = "email"
    PUSHNOTIFICATION = "pushnotification"
    VOICE = "voice"
    VIBER = "viber"


# Plain Literal (not MessageChannel) for MCP tool-facing signatures: pydantic
# emits Enum-typed fields as a `$ref` into `$defs`, which some simpler MCP
# clients' schema renderers (e.g. Zendesk's action-flow builder) don't resolve
# - they only look for `"enum"` inlined directly on the property, so the
# channel field silently loses its dropdown. Literal is inlined instead.
ChannelLiteral = Literal[tuple(c.value for c in MessageChannel)]


class EmailAddresses(BaseModel):
    """The Connect API "email" object - CC/BCC addresses."""

    cc: str | None = None
    bcc: str | None = None


# --- RCS rich content ("RCS Channel Parameters" section of the guide) ------


class RcsMedia(_CamelModel):
    file_url: str
    height: str | None = None


class RcsUrlAction(_CamelModel):
    url: str


class RcsDialAction(_CamelModel):
    phone_number: str


class RcsSuggestion(_CamelModel):
    text: str
    postback_data: str
    url_action: RcsUrlAction | None = None
    dial_action: RcsDialAction | None = None


class RcsCard(_CamelModel):
    title: str | None = None
    description: str | None = None
    media: RcsMedia | None = None
    suggestions: list[RcsSuggestion] | None = None


class RcsRichCard(_CamelModel):
    card_orientation: str | None = None
    card_width: str | None = None
    cards: list[RcsCard]


class RcsContent(_CamelModel):
    """The `"rcs"` object - sends an RCS message without a predefined template.

    Overrides `text`/`templateName` on `SendMessageRequest` when present.
    Provide exactly one of `text`, `media`, `rich_card`.
    """

    text: str | None = None
    media: RcsMedia | None = None
    rich_card: RcsRichCard | None = None
    suggestions: list[RcsSuggestion] | None = None

    @model_validator(mode="after")
    def _check_exactly_one_content_type(self) -> "RcsContent":
        provided = [v is not None for v in (self.text, self.media, self.rich_card)]
        if sum(provided) != 1:
            raise ValueError("Provide exactly one of 'text', 'media', or 'rich_card' for RCS content")
        if self.suggestions is not None and len(self.suggestions) > MAX_RCS_SUGGESTIONS:
            raise ValueError(f"RCS 'suggestions' supports a maximum of {MAX_RCS_SUGGESTIONS} entries")
        return self


# --- WhatsApp rich content ("whatsApp Channel Parameters" section) --------


class WhatsAppMedia(_CamelModel):
    """Shape shared by the WhatsApp image/video/document/audio content types."""

    url: str
    caption: str | None = None


class WhatsAppText(_CamelModel):
    body: str
    # The guide's own JSON example uses the literal key "preview_url" (not
    # camelCased like the rest of the API) - keep that exact alias.
    preview_url: bool | None = Field(default=None, alias="preview_url")


class WhatsAppLocation(_CamelModel):
    longitude: float
    latitude: float
    name: str | None = None
    address: str | None = None


class WhatsAppReaction(_CamelModel):
    message_id: str
    emoji: str


class WhatsAppContext(_CamelModel):
    message_id: str


class WhatsAppInteractiveHeader(_CamelModel):
    type: str
    text: str | None = None
    image: WhatsAppMedia | None = None
    document: WhatsAppMedia | None = None
    video: WhatsAppMedia | None = None


class WhatsAppInteractiveBody(_CamelModel):
    text: str


class WhatsAppInteractiveFooter(_CamelModel):
    text: str


class WhatsAppListRow(_CamelModel):
    postback_data: str
    title: str
    description: str | None = None


class WhatsAppListSection(_CamelModel):
    title: str | None = None
    rows: list[WhatsAppListRow]


class WhatsAppButton(_CamelModel):
    type: str = "reply"
    title: str
    postback_data: str


class WhatsAppInteractiveAction(_CamelModel):
    name: str | None = None
    sections: list[WhatsAppListSection] | None = None
    buttons: list[WhatsAppButton] | None = None


class WhatsAppInteractive(_CamelModel):
    """`interactive` object - `type` is `"button"` or `"list"`."""

    type: str
    header: WhatsAppInteractiveHeader | None = None
    body: WhatsAppInteractiveBody
    footer: WhatsAppInteractiveFooter | None = None
    action: WhatsAppInteractiveAction


class WhatsAppTemplateHeader(_CamelModel):
    type: str
    image: WhatsAppMedia | None = None
    document: WhatsAppMedia | None = None
    video: WhatsAppMedia | None = None
    parameters: list[str] | None = None


class WhatsAppTemplateBody(_CamelModel):
    parameters: list[str] | None = None


class WhatsAppTemplateButton(_CamelModel):
    type: str
    postback_data: str | None = None
    parameters: list[str] | None = None


class WhatsAppTemplate(_CamelModel):
    """`template` object - sends a pre-approved Meta/WABA template message."""

    name: str
    language: str
    header: WhatsAppTemplateHeader | None = None
    body: WhatsAppTemplateBody | None = None
    buttons: list[WhatsAppTemplateButton] | None = None


class WhatsAppContent(_CamelModel):
    """The `"whatsapp"` object - required for interactive/template/media/etc.

    `type` selects which of the other fields is populated, mirroring the
    Connect API's own discriminated-union shape (e.g. `type="image"` ->
    populate `image`). `contacts` and `sticker` are deep/rarely-used content
    types not modeled individually here - pass their raw JSON via `extra`.
    """

    type: str
    text: WhatsAppText | None = None
    image: WhatsAppMedia | None = None
    video: WhatsAppMedia | None = None
    document: WhatsAppMedia | None = None
    audio: WhatsAppMedia | None = None
    location: WhatsAppLocation | None = None
    reaction: WhatsAppReaction | None = None
    context: WhatsAppContext | None = None
    interactive: WhatsAppInteractive | None = None
    template: WhatsAppTemplate | None = None


# --- Voice rich content ("Voice Channel Parameters" section) --------------


class VoiceText2Voice(_CamelModel):
    before_password_text: str | None = None
    password: str | None = None
    after_password_text: str | None = None
    password_spoken_speed: int | None = Field(default=None, ge=0, le=2)
    loop: int | None = Field(default=None, ge=0, le=3)
    gender: int | None = Field(default=None, ge=1, le=2)
    language: str | None = None
    spoken_speed: int | None = Field(default=None, ge=0, le=2)


class VoiceCallControlObject(_CamelModel):
    id: int


class VoiceAudio(_CamelModel):
    url: str
    loop: int | None = Field(default=None, ge=0, le=3)


class VoiceContent(_CamelModel):
    """The `"voice"` object - text-to-speech, a Call Control Object, or an audio file."""

    # to_camel("text2voice") would produce "text2Voice" - override to match the
    # guide's literal key exactly.
    text2voice: VoiceText2Voice | None = Field(default=None, alias="text2voice")
    call_control_object: VoiceCallControlObject | None = None
    audio: VoiceAudio | None = None


# --- Push Notification content --------------------------------------------


class PushNotificationNotification(_CamelModel):
    title: str
    body: str


class PushNotificationContent(_CamelModel):
    """The `"pushNotification"` object.

    Live-tested confirmed shape: `title`/`body` nested under a `notification`
    object - the guide's flat `{title, body}` (no wrapper) was submitted
    successfully but the message ended up `UNDELIVERABLE`; only this nested
    shape actually reached `SENT`.
    """

    notification: PushNotificationNotification


class SendMessageRequest(BaseModel):
    """Real-time mode send payload: `POST {domain_url}/cgpapi/messages/{channel}`."""

    channel: MessageChannel
    destination: str = Field(..., description="Comma separated destinations, max 250 in real-time mode")
    text: str | None = None
    template_name: str | None = Field(default=None, max_length=100)
    key_values: str | None = Field(default=None, max_length=2000)
    client_message_id: str | None = Field(default=None, max_length=128)
    cost_centre: str | None = Field(default=None, max_length=100)
    reply_to_ton: int | None = None
    reply_to: str | None = None
    source: str | None = Field(default=None, max_length=50)
    destination_ton: int | None = None
    launch_timestamp: str | None = None
    validity_timestamp: str | None = None
    source_presentation: str | None = Field(default=None, max_length=2000)
    subject: str | None = Field(default=None, max_length=2000)
    email: EmailAddresses | None = None
    delay: int | None = None
    valid: int | None = None
    registered: int | None = Field(default=None, ge=0, le=5)
    fallback_message_type: str | None = None
    fallback_template_name: str | None = None
    rcs: RcsContent | None = None
    whatsapp: WhatsAppContent | None = None
    voice: VoiceContent | None = None
    push_notification: PushNotificationContent | None = None
    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator("destination")
    @classmethod
    def _check_destination_count(cls, value: str) -> str:
        count = len([d for d in value.split(",") if d.strip()])
        if count > MAX_REALTIME_DESTINATIONS:
            raise ValueError(
                f"Real-time mode supports a maximum of {MAX_REALTIME_DESTINATIONS} comma-separated "
                f"destinations, got {count}"
            )
        return value

    @model_validator(mode="after")
    def _check_content_and_limits(self) -> "SendMessageRequest":
        has_rich_content = any((self.rcs, self.whatsapp, self.voice, self.push_notification))
        if not self.text and not self.template_name and not has_rich_content:
            raise ValueError(
                "Either 'text', 'template_name', or channel-specific rich content "
                "('rcs'/'whatsapp'/'voice'/'push_notification') must be provided"
            )
        if self.text:
            limit = MAX_TEXT_LENGTH.get(self.channel.value)
            if limit and len(self.text) > limit:
                raise ValueError(f"'text' exceeds the {limit} character limit for channel '{self.channel.value}'")
        if self.reply_to_ton is not None and self.reply_to_ton not in VALID_REPLY_TO_TON:
            raise ValueError(f"'reply_to_ton' must be one of {sorted(VALID_REPLY_TO_TON)}")
        return self

    def to_payload(self) -> dict[str, Any]:
        """Build the Connect API JSON payload (camelCase field names)."""
        payload: dict[str, Any] = {"messageType": self.channel.value, "destination": self.destination}
        optional_fields = {
            "text": self.text,
            "templateName": self.template_name,
            "keyValues": self.key_values,
            "clientMessageId": self.client_message_id,
            "costCentre": self.cost_centre,
            "replyToTON": self.reply_to_ton,
            "replyTo": self.reply_to,
            "source": self.source,
            "destinationTon": self.destination_ton,
            "launchTimestamp": self.launch_timestamp,
            "validityTimestamp": self.validity_timestamp,
            "sourcePresentation": self.source_presentation,
            "subject": self.subject,
            "delay": self.delay,
            "valid": self.valid,
            "registered": self.registered,
            "fallbackMessageType": self.fallback_message_type,
            "fallbackTemplateName": self.fallback_template_name,
        }
        for key, value in optional_fields.items():
            if value is not None:
                payload[key] = value
        if self.email is not None:
            payload["email"] = self.email.model_dump(exclude_none=True)
        if self.rcs is not None:
            payload["rcs"] = self.rcs.to_payload()
        if self.whatsapp is not None:
            # Live-tested (2026-08-14): despite the guide's "whatsApp Channel
            # Parameters" section heading, the actual wire key is lowercase
            # "whatsapp" - camelCasing it breaks the server ("No message
            # content provided", 400102). Don't re-camelCase this again
            # without a live test proving it first.
            payload["whatsapp"] = self.whatsapp.to_payload()
        if self.voice is not None:
            payload["voice"] = self.voice.to_payload()
        if self.push_notification is not None:
            payload["pushNotification"] = self.push_notification.to_payload()
        payload.update(self.extra)
        return payload


class BatchStatusItem(BaseModel):
    """A single lookup item for `POST {domain_url}/cgpapi/batch/messages/status`."""

    id: int
    message_type: str = "SMS"

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.id, "messageType": self.message_type}


class BroadcastEndpoint(BaseModel):
    """A single Connect API broadcast "endpoint" (list, contact or group reference)."""

    type: int
    id: int


class BroadcastBatchOptions(BaseModel):
    """Overrides the default broadcast batching (500/batch, 10s sleep, 100k max)."""

    batch_size: int | None = None
    sleep_duration: int | None = None
    max_destinations: int | None = None

    def to_payload(self) -> dict[str, Any]:
        payload = {
            "batchSize": self.batch_size,
            "sleepDuration": self.sleep_duration,
            "maxDestinations": self.max_destinations,
        }
        return {k: v for k, v in payload.items() if v is not None}


class SendBroadcastRequest(BaseModel):
    """`POST {domain_url}/cgpapi/broadcast/sms` payload."""

    text: str
    endpoints: list[BroadcastEndpoint]
    registered: bool | None = None
    batch_options: BroadcastBatchOptions | None = None

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "message": {"text": self.text},
            "endpoints": [e.model_dump() for e in self.endpoints],
        }
        if self.registered is not None:
            payload["registered"] = str(self.registered).lower()
        if self.batch_options is not None:
            batch_options_payload = self.batch_options.to_payload()
            if batch_options_payload:
                payload["batchOptions"] = batch_options_payload
        return payload
