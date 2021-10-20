"""
Add a custom version of the gRPC/protobuf content view, which parses
protobuf messages based on a user defined rule set.

"""
from mitmproxy import contentviews
from mitmproxy.contentviews.grpc import ViewGrpcProtobuf, ViewConfig, ProtoParser

config: ViewConfig = ViewConfig()
config.parser_rules = [
    ProtoParser.ParserRuleRequest(
        name = "Google Play",
        # note on flowfilter: for tflow the port gets appended to the URL's host part
        filter = "play.googleapis.com/log/batch",
        field_definitions=[
            ProtoParser.ParserFieldDefinition(
                tag="1.5",
                name="repeated",
                intended_decoding=ProtoParser.DecodedTypes.message,
                as_packed=True
            ),
            ProtoParser.ParserFieldDefinition(
                tag="1.5.16.2.2",
                name="repeated varint",
                intended_decoding=ProtoParser.DecodedTypes.int32,
                as_packed=True
            ),
        ]
    ),

    ProtoParser.ParserRuleRequest(
        name = "Google Play",
        filter = "play-fe.googleapis.com/fdfe/details",
        field_definitions=[
            ProtoParser.ParserFieldDefinition(tag="xxx", name="display info"),
        ]
    ),
    ProtoParser.ParserRuleResponse(
        name = "Google Play",
        filter = "play-fe.googleapis.com/fdfe/details",
        # 1.2.4.13.1.70

        field_definitions=[
            ProtoParser.ParserFieldDefinition(tag="1.2.4.13.1.70", name="exact download count"),
            ProtoParser.ParserFieldDefinition(tag="1.2.4.13.1.77", name="rounded download count (short)"),
            ProtoParser.ParserFieldDefinition(tag="1.2.4.13.1.78", name="rounded download count"),
            ProtoParser.ParserFieldDefinition(tag="1.2.4.14.3", name="review count overall"),
            ProtoParser.ParserFieldDefinition(tag="1.2.4.14.4", name="review count rate 1"),
            ProtoParser.ParserFieldDefinition(tag="1.2.4.14.5", name="review count rate 2"),
            ProtoParser.ParserFieldDefinition(tag="1.2.4.14.6", name="review count rate 3"),
            ProtoParser.ParserFieldDefinition(tag="1.2.4.14.7", name="review count rate 4"),
            ProtoParser.ParserFieldDefinition(tag="1.2.4.14.8", name="review count rate 5"),
            ProtoParser.ParserFieldDefinition(tag="1.2.4.14.17", name="average rating"),
        ]
    ),

    ProtoParser.ParserRuleRequest(
        name = "Google Play",
        filter = "play-fe.googleapis.com/fdfe/getItems",
        field_definitions=[
            ProtoParser.ParserFieldDefinition(tag="xxx", name="display info"),
        ]
    ),
    ProtoParser.ParserRuleResponse(
        name = "Google Play",
        filter = "play-fe.googleapis.com/fdfe/getItems",
        field_definitions=[
            ProtoParser.ParserFieldDefinition(tag="11.2.3.8.1", name="download count words"),
            ProtoParser.ParserFieldDefinition(tag="11.2.3.8.2", name="download count rounded"),
            ProtoParser.ParserFieldDefinition(tag="11.2.3.8.3", name="download count ? ;-) ?"),
        ]
    ),

    ProtoParser.ParserRuleRequest(
        name = "Google request",
        filter = "GellerService/BatchSync",
        field_definitions=[
            ProtoParser.ParserFieldDefinition(tag="3.1.4.2", name="display info"),
            ProtoParser.ParserFieldDefinition(tag="3.1.4.2.1", name="res_x"),
            ProtoParser.ParserFieldDefinition(tag="3.1.4.2.3", name="res_y"),
            ProtoParser.ParserFieldDefinition(tag="3.1.4.2.3", name="android version?"),
            ProtoParser.ParserFieldDefinition(tag="3.1.4.2.5", name="dpi"),
        ]
    ),
    ProtoParser.ParserRuleRequest(
        name = "Snapchat map viewport",
        filter = "aws.api.snapchat.com/map/viewport/getInfo",
        field_definitions=[
            ProtoParser.ParserFieldDefinition(tag="1", name="viewport to GPS"),
            ProtoParser.ParserFieldDefinition(tag="1.1", name="viewport lower left", intended_decoding=ProtoParser.DecodedTypes.string),
            ProtoParser.ParserFieldDefinition(tag="1.2", name="viewport upper right", intended_decoding=ProtoParser.DecodedTypes.string),
            ProtoParser.ParserFieldDefinition(tag="1", tag_prefixes=["1.1.", "1.2."], name="latitude", intended_decoding=ProtoParser.DecodedTypes.double),  # noqa: E501
            ProtoParser.ParserFieldDefinition(tag="2", tag_prefixes=["1.1.", "1.2."], name="longitude", intended_decoding=ProtoParser.DecodedTypes.double),  # noqa: E501
            ProtoParser.ParserFieldDefinition(tag="2", name="zoom", intended_decoding=ProtoParser.DecodedTypes.double),  # noqa: E501
        ]
    ),
    # Ref: https://stackoverflow.com/questions/54461349/how-to-decrypt-firebase-requests-to-app-measurement-com/54463682#54463682
    # 10-14 12:05:16.869 26003 26086 I FA      : App measurement initialized, version: 43029
    # 10-14 12:05:16.869 26003 26086 I FA      : To enable debug logging run: adb shell setprop log.tag.FA VERBOSE
    # 10-14 12:05:16.871 26003 26086 I FA      : To enable faster debug mode event logging run:
    # 10-14 12:05:16.871 26003 26086 I FA      :   adb shell setprop debug.firebase.analytics.app com.reddit.frontpage

    ProtoParser.ParserRuleRequest(
        name = "App Measurement (header indicates x-www-form-urlencoded)",
        filter = "//app-measurement.com/a",
        field_definitions=[
            ProtoParser.ParserFieldDefinition(tag="1.2", name="-> logmessage entries"),
            ProtoParser.ParserFieldDefinition(tag="1.2.1", name="--> entry"),
            ProtoParser.ParserFieldDefinition(tag="1.2.1.1", name="log type"),
            ProtoParser.ParserFieldDefinition(tag="1.2.1.2", name="log value (string)"),
            ProtoParser.ParserFieldDefinition(tag="1.2.1.3", name="log value (number)"),
            ProtoParser.ParserFieldDefinition(tag="1.3", name="--> event"),
            ProtoParser.ParserFieldDefinition(tag="1.3.1", name="timestamp millis"),
            ProtoParser.ParserFieldDefinition(tag="1.3.2", name="event type"),
            ProtoParser.ParserFieldDefinition(tag="1.3.4", name="event value"),
            ProtoParser.ParserFieldDefinition(tag="1.2.2", name="error result"),
            ProtoParser.ParserFieldDefinition(tag="1.2.3", name="timestamp end"),
            ProtoParser.ParserFieldDefinition(tag="1.2.4", name="timestamp start"),
            ProtoParser.ParserFieldDefinition(tag="1.8", name="device_info.operating_system"),
            ProtoParser.ParserFieldDefinition(tag="1.9", name="device_info.operating_system_version"),
            ProtoParser.ParserFieldDefinition(tag="1.10", name="device model name"),
            ProtoParser.ParserFieldDefinition(tag="1.11", name="device.language"),
            ProtoParser.ParserFieldDefinition(tag="1.12", name=""),
            ProtoParser.ParserFieldDefinition(tag="1.14", name="app package"),
            ProtoParser.ParserFieldDefinition(tag="1.16", name="app version"),
            ProtoParser.ParserFieldDefinition(tag="1.17", name="app measurement version"),
            ProtoParser.ParserFieldDefinition(tag="1.19", name="device.advertising_id"),
            ProtoParser.ParserFieldDefinition(tag="1.21", name="app instance id"),
            ProtoParser.ParserFieldDefinition(tag="1.22", name="unknown id - per app"),
            ProtoParser.ParserFieldDefinition(tag="1.25", name="google app id"),
        ]
    ),
    ProtoParser.ParserRuleRequest(
        name = "Geo coordinate lookup request",
        # note on flowfilter: for tflow the port gets appended to the URL's host part
        filter = "example\\.com.*/ReverseGeocode",
        field_definitions=[
            ProtoParser.ParserFieldDefinition(tag="1", name="position"),
            ProtoParser.ParserFieldDefinition(tag="1.1", name="latitude", intended_decoding=ProtoParser.DecodedTypes.double),
            ProtoParser.ParserFieldDefinition(tag="1.2", name="longitude", intended_decoding=ProtoParser.DecodedTypes.double),
            ProtoParser.ParserFieldDefinition(tag="3", name="country"),
            ProtoParser.ParserFieldDefinition(tag="7", name="app"),
        ]
    ),
    ProtoParser.ParserRuleResponse(
        name = "Geo coordinate lookup response",
        # note on flowfilter: for tflow the port gets appended to the URL's host part
        filter = "example\\.com.*/ReverseGeocode",
        field_definitions=[
            ProtoParser.ParserFieldDefinition(tag="1.2", name="address"),
            ProtoParser.ParserFieldDefinition(tag="1.3", name="address array element"),
            ProtoParser.ParserFieldDefinition(tag="1.3.1", name="unknown bytes", intended_decoding=ProtoParser.DecodedTypes.bytes),
            ProtoParser.ParserFieldDefinition(tag="1.3.2", name="element value long"),
            ProtoParser.ParserFieldDefinition(tag="1.3.3", name="element value short"),
            ProtoParser.ParserFieldDefinition(tag="", tag_prefixes=["1.5.1", "1.5.3", "1.5.4", "1.5.5", "1.5.6"], name="position"),
            ProtoParser.ParserFieldDefinition(tag=".1", tag_prefixes=["1.5.1", "1.5.3", "1.5.4", "1.5.5", "1.5.6"], name="latitude", intended_decoding=ProtoParser.DecodedTypes.double),  # noqa: E501
            ProtoParser.ParserFieldDefinition(tag=".2", tag_prefixes=["1.5.1", "1.5.3", "1.5.4", "1.5.5", "1.5.6"], name="longitude", intended_decoding=ProtoParser.DecodedTypes.double),  # noqa: E501
            ProtoParser.ParserFieldDefinition(tag="7", name="app"),
        ]
    ),
]


class ViewGrpcWithRules(ViewGrpcProtobuf):
    name = "customized gRPC/protobuf"

    def __init__(self) -> None:
        super().__init__(config=config)

    def __call__(self, *args, **kwargs) -> contentviews.TViewResult:
        heading, lines = super().__call__(*args, **kwargs)
        return heading + " (addon with custom rules)", lines

    def render_priority(self, *args, **kwargs) -> float:
        # increase priority above default gRPC view
        s_prio = super().render_priority(*args, **kwargs)
        return s_prio + 1 if s_prio > 0 else s_prio


view = ViewGrpcWithRules()


def load(l):
    existing = contentviews.get(view.name)
    if existing is not None:
        contentviews.remove(existing)
    contentviews.add(view)


def done():
    contentviews.remove(view)
