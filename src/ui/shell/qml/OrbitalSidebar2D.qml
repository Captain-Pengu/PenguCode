import QtQuick

Rectangle {
    id: root
    color: "transparent"

    property var allItems: bladeSidebarBridge.allOrbs
    property var frontItems: bladeSidebarBridge.visibleOrbs
    property int transitionSerial: bladeSidebarBridge.transitionSerial
    property int transitionDirection: bladeSidebarBridge.transitionDirection
    property real orbitCenterX: 118
    property real orbitCenterY: height * 0.5
    property real orbitRadiusX: Math.min(98, width * 0.25)
    property real orbitRadiusY: Math.min(188, height * 0.30)
    property real planetCoreSize: 72
    property real cardWidth: Math.min(138, width - 250)
    property real cardHeight: 58
    property real cardGap: 22
    property var frontAngles: [-34, 0, 34]
    property real transitionKick: 0
    property real planetPulse: 0

    function clamp(value, low, high) {
        return Math.max(low, Math.min(high, value))
    }

    function ellipsePointForAngle(angleDeg) {
        var r = angleDeg * Math.PI / 180.0
        return Qt.point(
            orbitCenterX + Math.cos(r) * orbitRadiusX,
            orbitCenterY + Math.sin(r) * orbitRadiusY
        )
    }

    function depthForAngle(angleDeg) {
        var r = angleDeg * Math.PI / 180.0
        return (Math.cos(r) + 1.0) * 0.5
    }

    function ringItemAt(idx) {
        return idx < allItems.length ? allItems[idx] : null
    }

    function frontItemAt(idx) {
        return idx < frontItems.length ? frontItems[idx] : null
    }

    function frontAnchorForItem(item) {
        if (!item)
            return Qt.point(0, 0)
        var slot = item.slot >= 0 ? item.slot : 1
        return ellipsePointForAngle(frontAngles[Math.max(0, Math.min(2, slot))])
    }

    function cardLeftForAnchor(anchorX) {
        return clamp(anchorX + cardGap, width * 0.56, width - cardWidth - 16)
    }

    function cardTopForAnchor(anchorY) {
        return anchorY - (cardHeight * 0.5)
    }

    onTransitionSerialChanged: {
        transitionKick = transitionDirection >= 0 ? 34 : -34
        planetPulse = 1.0
        settleAnim.restart()
        planetAnim.restart()
    }

    NumberAnimation {
        id: settleAnim
        target: root
        property: "transitionKick"
        from: root.transitionKick
        to: 0
        duration: 380
        easing.type: Easing.OutCubic
    }

    NumberAnimation {
        id: planetAnim
        target: root
        property: "planetPulse"
        from: 1.0
        to: 0.0
        duration: 520
        easing.type: Easing.OutQuad
    }

    Rectangle {
        anchors.fill: parent
        radius: 18
        color: bladeSidebarBridge.panelColor
        border.width: 1
        border.color: Qt.rgba(1, 1, 1, 0.09)
    }

    Rectangle {
        anchors.left: parent.left
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        width: root.width * 0.55
        radius: 18
        color: "transparent"
        gradient: Gradient {
            GradientStop { position: 0.0; color: Qt.rgba(bladeSidebarBridge.accentColor.r, bladeSidebarBridge.accentColor.g, bladeSidebarBridge.accentColor.b, 0.10) }
            GradientStop { position: 0.55; color: Qt.rgba(bladeSidebarBridge.accentColor.r, bladeSidebarBridge.accentColor.g, bladeSidebarBridge.accentColor.b, 0.03) }
            GradientStop { position: 1.0; color: Qt.rgba(0.0, 0.0, 0.0, 0.0) }
        }
    }

    Item {
        x: orbitCenterX - 120
        y: orbitCenterY - 120
        width: 240
        height: 240

        Rectangle {
            anchors.centerIn: parent
            width: 210 + (root.planetPulse * 12)
            height: 210 + (root.planetPulse * 12)
            radius: width * 0.5
            color: Qt.rgba(bladeSidebarBridge.accentColor.r, bladeSidebarBridge.accentColor.g, bladeSidebarBridge.accentColor.b, 0.05)
            Behavior on width { NumberAnimation { duration: 300; easing.type: Easing.OutQuad } }
            Behavior on height { NumberAnimation { duration: 300; easing.type: Easing.OutQuad } }
        }

        Rectangle {
            anchors.centerIn: parent
            width: 150 + (root.planetPulse * 10)
            height: 150 + (root.planetPulse * 10)
            radius: width * 0.5
            color: Qt.rgba(bladeSidebarBridge.accentColor.r, bladeSidebarBridge.accentColor.g, bladeSidebarBridge.accentColor.b, 0.12)
            Behavior on width { NumberAnimation { duration: 280; easing.type: Easing.OutQuad } }
            Behavior on height { NumberAnimation { duration: 280; easing.type: Easing.OutQuad } }
        }

        Rectangle {
            anchors.centerIn: parent
            width: planetCoreSize
            height: planetCoreSize
            radius: planetCoreSize * 0.5
            gradient: Gradient {
                GradientStop { position: 0.0; color: "#ffdbe5" }
                GradientStop { position: 0.58; color: "#fff5f8" }
                GradientStop { position: 1.0; color: "#f0c5d3" }
            }
            border.width: 1
            border.color: Qt.rgba(1, 1, 1, 0.18)
        }
    }

    Repeater {
        model: 72

        delegate: Rectangle {
            property real angleDeg: (index / 72.0) * 360.0
            property point p: root.ellipsePointForAngle(angleDeg + (root.transitionKick * 0.35))
            property real d: root.depthForAngle(angleDeg)
            width: ((index % 9 === 0) ? 5 : 3) * (0.72 + (d * 0.46))
            height: width
            radius: width * 0.5
            x: p.x - (width * 0.5)
            y: p.y - (height * 0.5)
            color: index % 9 === 0
                ? Qt.rgba(bladeSidebarBridge.accentColor.r, bladeSidebarBridge.accentColor.g, bladeSidebarBridge.accentColor.b, 0.16 + (d * 0.26))
                : Qt.rgba(bladeSidebarBridge.edgeGlowColor.r, bladeSidebarBridge.edgeGlowColor.g, bladeSidebarBridge.edgeGlowColor.b, 0.04 + (d * 0.10))
            Behavior on x { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
            Behavior on y { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
        }
    }

    Repeater {
        model: allItems.length

        delegate: Item {
            property var item: root.ringItemAt(index)
            property point p: item ? root.ellipsePointForAngle(item.angle + (root.transitionKick * 0.42)) : Qt.point(0, 0)
            property real d: item ? root.depthForAngle(item.angle) : 0
            visible: item !== null && !item.front
            x: p.x - 6
            y: p.y - 6
            width: 12
            height: 12
            opacity: 0.28 + (d * 0.46)

            Behavior on x { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
            Behavior on y { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
            Behavior on opacity { NumberAnimation { duration: 220 } }

            Rectangle {
                anchors.centerIn: parent
                width: 8 * (0.78 + (parent.d * 0.38))
                height: width
                radius: width * 0.5
                color: Qt.rgba(bladeSidebarBridge.edgeGlowColor.r, bladeSidebarBridge.edgeGlowColor.g, bladeSidebarBridge.edgeGlowColor.b, 0.10 + (parent.d * 0.22))
            }
        }
    }

    Repeater {
        model: frontItems.length

        delegate: Item {
            property var item: root.frontItemAt(index)
            property point anchorPoint: root.frontAnchorForItem(item)
            property real animatedX: anchorPoint.x + (root.transitionKick * 0.30)
            property real animatedY: anchorPoint.y + ((index - 1) * Math.abs(root.transitionKick) * 0.08)
            property bool hovered: false
            visible: item !== null
            x: 0
            y: 0
            width: root.width
            height: root.height

            Rectangle {
                x: parent.animatedX - 20
                y: parent.animatedY - 20
                width: parent.hovered || (item && item.active) ? 40 : 36
                height: width
                radius: width * 0.5
                color: item && item.active ? bladeSidebarBridge.accentColor : Qt.rgba(1, 1, 1, 0.06)
                border.width: 1
                border.color: Qt.rgba(1, 1, 1, item && item.active ? 0.35 : 0.16)
                Behavior on x { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
                Behavior on y { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
                Behavior on width { NumberAnimation { duration: 140; easing.type: Easing.OutQuad } }
                Behavior on height { NumberAnimation { duration: 140; easing.type: Easing.OutQuad } }
            }

            Rectangle {
                x: parent.animatedX - 12
                y: parent.animatedY - 12
                width: parent.hovered || (item && item.active) ? 26 : 24
                height: width
                radius: width * 0.5
                color: "#eef4fb"
                Behavior on x { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
                Behavior on y { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
                Behavior on width { NumberAnimation { duration: 140; easing.type: Easing.OutQuad } }
                Behavior on height { NumberAnimation { duration: 140; easing.type: Easing.OutQuad } }
            }

            Rectangle {
                x: parent.animatedX + 14
                y: parent.animatedY - 1
                width: root.cardLeftForAnchor(parent.animatedX) - (parent.animatedX + 14)
                height: 2
                radius: 1
                color: Qt.rgba(1, 1, 1, 0.18)
                Behavior on x { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
                Behavior on y { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
                Behavior on width { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
            }

            Rectangle {
                x: root.cardLeftForAnchor(parent.animatedX)
                y: root.cardTopForAnchor(parent.animatedY)
                width: root.cardWidth
                height: root.cardHeight
                radius: 16
                color: item && item.active
                    ? Qt.rgba(bladeSidebarBridge.accentColor.r, bladeSidebarBridge.accentColor.g, bladeSidebarBridge.accentColor.b, 0.88)
                    : Qt.rgba(1, 1, 1, 0.07)
                border.width: 1
                border.color: Qt.rgba(1, 1, 1, item && item.active ? 0.24 : 0.12)
                scale: parent.hovered ? 1.03 : 1.0
                Behavior on x { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
                Behavior on y { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
                Behavior on scale { NumberAnimation { duration: 120; easing.type: Easing.OutQuad } }

                MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    onEntered: parent.parent.hovered = true
                    onExited: parent.parent.hovered = false
                    onClicked: bladeSidebarBridge.selectOrb(item.index)
                }

                Row {
                    anchors.fill: parent
                    anchors.margins: 12
                    spacing: 10

                    Rectangle {
                        width: 26
                        height: 26
                        radius: 13
                        anchors.verticalCenter: parent.verticalCenter
                        color: Qt.rgba(1, 1, 1, item && item.active ? 0.14 : 0.10)

                        Text {
                            anchors.centerIn: parent
                            text: item ? item.glyph : ""
                            color: "#f4f7fb"
                            font.pixelSize: 14
                            font.bold: true
                        }
                    }

                    Column {
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: 3

                        Text {
                            text: item ? item.name : ""
                            color: "#f4f7fb"
                            font.pixelSize: 12
                            font.bold: true
                            elide: Text.ElideRight
                            width: root.cardWidth - 64
                        }

                        Text {
                            text: item ? item.description : ""
                            color: Qt.rgba(1, 1, 1, 0.74)
                            font.pixelSize: 10
                            elide: Text.ElideRight
                            width: root.cardWidth - 64
                        }
                    }
                }
            }
        }
    }

    Rectangle {
        x: root.width - 64
        y: 96
        width: 42
        height: 42
        radius: 12
        color: Qt.rgba(1, 1, 1, 0.06)
        border.width: 1
        border.color: Qt.rgba(1, 1, 1, 0.12)

        MouseArea {
            anchors.fill: parent
            onClicked: bladeSidebarBridge.pageUp()
        }

        Text {
            anchors.centerIn: parent
            text: "\u25B2"
            color: "#eef4fb"
            font.pixelSize: 12
        }
    }

    Rectangle {
        x: root.width - 64
        y: root.height - 70
        width: 42
        height: 42
        radius: 12
        color: Qt.rgba(1, 1, 1, 0.06)
        border.width: 1
        border.color: Qt.rgba(1, 1, 1, 0.12)

        MouseArea {
            anchors.fill: parent
            onClicked: bladeSidebarBridge.pageDown()
        }

        Text {
            anchors.centerIn: parent
            text: "\u25BC"
            color: "#eef4fb"
            font.pixelSize: 12
        }
    }
}
