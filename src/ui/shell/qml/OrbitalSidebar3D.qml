import QtQuick
import QtQuick3D

Rectangle {
    id: root
    color: "transparent"

    property var allItems: bladeSidebarBridge.allOrbs
    property var frontItems: bladeSidebarBridge.visibleOrbs
    property var previousItems: bladeSidebarBridge.previousVisibleOrbs

    property real transitionProgress: 1.0
    property real transitionFade: 1.0
    property bool transitionRunning: false
    property real planetPulse: 0.0
    property real planetSpinKick: 0.0

    property real orbitCenterX: 112
    property real orbitCenterY: root.height * 0.5
    property real orbitRadiusX: Math.min(104, root.width * 0.27)
    property real orbitRadiusY: Math.min(192, root.height * 0.29)

    property real planetCoreSize: Math.min(74, orbitRadiusX * 0.70)
    property real planetHaloSize: planetCoreSize * 2.35
    property real planetAuraSize: planetCoreSize * 3.15

    property real cardWidth: Math.min(134, root.width - 254)
    property real cardHeight: 58
    property real cardGap: 26

    property var frontAngles: [-34, 0, 34]
    property real orbitShiftAngle: 146

    function clamp(value, low, high) {
        return Math.max(low, Math.min(high, value))
    }

    function lerp(a, b, t) {
        return a + ((b - a) * t)
    }

    function ringItemAt(idx) {
        return idx < allItems.length ? allItems[idx] : null
    }

    function frontItemAt(idx) {
        return idx < frontItems.length ? frontItems[idx] : null
    }

    function previousItemAt(idx) {
        return idx < previousItems.length ? previousItems[idx] : null
    }

    function isIndexInList(indexValue, list) {
        for (var i = 0; i < list.length; ++i) {
            if (list[i] && list[i].index === indexValue)
                return true
        }
        return false
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

    function scaleForAngle(angleDeg, minScale, maxScale) {
        return lerp(minScale, maxScale, depthForAngle(angleDeg))
    }

    function opacityForAngle(angleDeg, minOpacity, maxOpacity) {
        return lerp(minOpacity, maxOpacity, depthForAngle(angleDeg))
    }

    function frontAngleForSlot(slot) {
        var safeSlot = Math.max(0, Math.min(2, slot))
        return frontAngles[safeSlot]
    }

    function incomingAngleForSlot(slot) {
        return frontAngleForSlot(slot) - (bladeSidebarBridge.transitionDirection * orbitShiftAngle)
    }

    function outgoingAngleForSlot(slot) {
        return frontAngleForSlot(slot) + (bladeSidebarBridge.transitionDirection * orbitShiftAngle)
    }

    function currentFrontAngle(item) {
        if (!item)
            return 0

        var slot = item.slot >= 0 ? item.slot : 1
        var target = frontAngleForSlot(slot)
        if (!transitionRunning)
            return target

        return lerp(incomingAngleForSlot(slot), target, transitionProgress)
    }

    function previousFrontAngle(item) {
        if (!item)
            return 0

        var slot = item.slot >= 0 ? item.slot : 1
        return lerp(frontAngleForSlot(slot), outgoingAngleForSlot(slot), transitionProgress)
    }

    function frontAnchorForItem(item, previousLayer) {
        var angle = previousLayer ? previousFrontAngle(item) : currentFrontAngle(item)
        return ellipsePointForAngle(angle)
    }

    function cardLeftForAnchor(anchorX) {
        return clamp(anchorX + cardGap, root.width * 0.55, root.width - cardWidth - 14)
    }

    function cardTopForAnchor(anchorY) {
        return anchorY - (cardHeight * 0.5)
    }

    ParallelAnimation {
        id: transitionAnimation
        running: false
        onStarted: root.transitionRunning = true
        onFinished: root.transitionRunning = false

        SequentialAnimation {
            NumberAnimation {
                target: root
                property: "transitionProgress"
                from: 0
                to: 0.74
                duration: 520
                easing.type: Easing.InOutSine
            }
            NumberAnimation {
                target: root
                property: "transitionProgress"
                to: 1
                duration: 420
                easing.type: Easing.OutBack
            }
        }

        SequentialAnimation {
            NumberAnimation {
                target: root
                property: "transitionFade"
                from: 0.68
                to: 1
                duration: 360
                easing.type: Easing.OutCubic
            }
            PauseAnimation {
                duration: 580
            }
        }
    }

    SequentialAnimation {
        id: planetPulseAnimation
        running: false
        NumberAnimation {
            target: root
            property: "planetPulse"
            from: 0.0
            to: 1.0
            duration: 180
            easing.type: Easing.OutCubic
        }
        NumberAnimation {
            target: root
            property: "planetPulse"
            to: 0.0
            duration: 540
            easing.type: Easing.OutQuad
        }
    }

    SequentialAnimation {
        id: planetSpinAnimation
        running: false
        NumberAnimation {
            target: root
            property: "planetSpinKick"
            from: 0.0
            to: bladeSidebarBridge.transitionDirection > 0 ? 10.0 : -10.0
            duration: 220
            easing.type: Easing.OutCubic
        }
        NumberAnimation {
            target: root
            property: "planetSpinKick"
            to: 0.0
            duration: 560
            easing.type: Easing.OutBack
        }
    }

    Connections {
        target: bladeSidebarBridge
        function onTransitionChanged() {
            if (bladeSidebarBridge.transitionDirection === 0)
                return
            root.transitionProgress = 0
            root.transitionFade = 0.68
            transitionAnimation.restart()
            planetPulseAnimation.restart()
            planetSpinAnimation.restart()
        }
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

    View3D {
        anchors.left: parent.left
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        width: 240
        anchors.topMargin: 24
        anchors.bottomMargin: 24
        camera: camera
        renderMode: View3D.Offscreen

        environment: SceneEnvironment {
            backgroundMode: SceneEnvironment.Transparent
            antialiasingMode: SceneEnvironment.MSAA
            antialiasingQuality: SceneEnvironment.VeryHigh
        }

        PerspectiveCamera {
            id: camera
            position: Qt.vector3d(0, 0, 900)
            clipNear: 1
            clipFar: 5000
        }

        DirectionalLight {
            brightness: 1.5
            eulerRotation.x: -18
            eulerRotation.y: -14
            ambientColor: Qt.rgba(0.14, 0.14, 0.20, 1.0)
        }

        PointLight {
            position: Qt.vector3d(80, -50, 280)
            brightness: 30
            color: "#ffe8ef"
        }

        Node {
            eulerRotation.z: root.planetSpinKick
            position: Qt.vector3d(-92, 0, -120)

            NumberAnimation on eulerRotation.z {
                from: -2
                to: 2
                duration: 6800
                loops: Animation.Infinite
                easing.type: Easing.InOutSine
            }

            Model {
                source: "#Sphere"
                scale: Qt.vector3d(0.42, 0.42, 0.42)
                materials: PrincipledMaterial {
                    baseColor: bladeSidebarBridge.accentColor
                    opacity: 0.04
                    emissiveFactor: Qt.vector3d(0.25, 0.05, 0.08)
                    lighting: PrincipledMaterial.NoLighting
                }
            }
        }
    }

    Item {
        x: orbitCenterX - (planetAuraSize * 0.5)
        y: orbitCenterY - (planetAuraSize * 0.5)
        width: planetAuraSize
        height: planetAuraSize
        scale: 1.0 + (planetPulse * 0.045)
        rotation: planetSpinKick * 0.18

        Rectangle {
            anchors.centerIn: parent
            width: planetAuraSize * (1.0 + (planetPulse * 0.10))
            height: width
            radius: width * 0.5
            color: Qt.rgba(bladeSidebarBridge.accentColor.r, bladeSidebarBridge.accentColor.g, bladeSidebarBridge.accentColor.b, 0.07 + (planetPulse * 0.04))
        }

        Rectangle {
            anchors.centerIn: parent
            width: planetHaloSize * (1.0 + (planetPulse * 0.12))
            height: width
            radius: width * 0.5
            color: Qt.rgba(bladeSidebarBridge.accentColor.r, bladeSidebarBridge.accentColor.g, bladeSidebarBridge.accentColor.b, 0.16 + (planetPulse * 0.08))
        }

        Rectangle {
            anchors.centerIn: parent
            width: planetCoreSize * 1.35
            height: planetCoreSize * 1.35
            radius: width * 0.5
            color: Qt.rgba(1.0, 0.86, 0.91, 0.18)
        }

        Rectangle {
            anchors.centerIn: parent
            width: planetCoreSize
            height: planetCoreSize
            radius: width * 0.5
            gradient: Gradient {
                GradientStop { position: 0.0; color: "#ffdbe5" }
                GradientStop { position: 0.58; color: "#fff5f8" }
                GradientStop { position: 1.0; color: "#f0c5d3" }
            }
            border.width: 1
            border.color: Qt.rgba(1, 1, 1, 0.14 + (planetPulse * 0.10))
        }

        Rectangle {
            anchors.centerIn: parent
            x: -planetCoreSize * 0.10
            y: -planetCoreSize * 0.08
            width: planetCoreSize * 0.58
            height: planetCoreSize * 0.20
            radius: height * 0.5
            rotation: -18
            color: Qt.rgba(1.0, 0.98, 1.0, 0.16)
        }

        Rectangle {
            anchors.centerIn: parent
            x: planetCoreSize * 0.12
            y: planetCoreSize * 0.10
            width: planetCoreSize * 0.26
            height: width
            radius: width * 0.5
            color: Qt.rgba(0.74, 0.42, 0.50, 0.18)
            border.width: 1
            border.color: Qt.rgba(1, 1, 1, 0.06)
        }

        Rectangle {
            anchors.centerIn: parent
            x: -planetCoreSize * 0.20
            y: planetCoreSize * 0.16
            width: planetCoreSize * 0.14
            height: width
            radius: width * 0.5
            color: Qt.rgba(0.68, 0.34, 0.42, 0.14)
        }

        Rectangle {
            anchors.centerIn: parent
            x: -planetCoreSize * 0.16
            y: -planetCoreSize * 0.18
            width: planetCoreSize * 0.18
            height: width
            radius: width * 0.5
            color: Qt.rgba(1, 1, 1, 0.14)
        }
    }

    Repeater {
        model: 72

        delegate: Rectangle {
            property real angleDeg: (index / 72.0) * 360.0
            property point p: root.ellipsePointForAngle(angleDeg)
            property real dotScale: root.scaleForAngle(angleDeg, 0.72, 1.18)
            width: (index % 9 === 0 ? 5 : 3) * dotScale
            height: width
            radius: width * 0.5
            x: p.x - (width * 0.5)
            y: p.y - (height * 0.5)
            color: index % 9 === 0
                ? Qt.rgba(bladeSidebarBridge.accentColor.r, bladeSidebarBridge.accentColor.g, bladeSidebarBridge.accentColor.b, root.opacityForAngle(angleDeg, 0.14, 0.40))
                : Qt.rgba(bladeSidebarBridge.edgeGlowColor.r, bladeSidebarBridge.edgeGlowColor.g, bladeSidebarBridge.edgeGlowColor.b, root.opacityForAngle(angleDeg, 0.05, 0.15))
        }
    }

    Repeater {
        model: allItems.length

        delegate: Item {
            property var item: root.ringItemAt(index)
            property point p: item ? root.ellipsePointForAngle(item.angle) : Qt.point(0, 0)
            property real depth: item ? root.depthForAngle(item.angle) : 0
            visible: item !== null
                     && !item.front
                     && !root.isIndexInList(item.index, root.previousItems)
            width: 14
            height: 14
            x: p.x - 7
            y: p.y - 7
            scale: root.scaleForAngle(item ? item.angle : 0, 0.72, 1.16)
            opacity: root.opacityForAngle(item ? item.angle : 0, 0.30, 0.92)
            z: depth

            Rectangle {
                anchors.centerIn: parent
                x: 1.5
                y: 2
                width: item && item.active ? 10 : 8
                height: width
                radius: width * 0.5
                color: Qt.rgba(0.0, 0.0, 0.0, item && item.active ? 0.18 : 0.10)
            }

            Rectangle {
                anchors.centerIn: parent
                width: item && item.active ? 12 : 10
                height: width
                radius: width * 0.5
                color: Qt.rgba(bladeSidebarBridge.accentColor.r, bladeSidebarBridge.accentColor.g, bladeSidebarBridge.accentColor.b, item && item.active ? 0.48 : 0.20)
            }

            Rectangle {
                anchors.centerIn: parent
                width: item && item.active ? 7 : 5
                height: width
                radius: width * 0.5
                color: item && item.active ? "#fff4f8" : Qt.rgba(0.90, 0.92, 0.96, 0.62)
            }
        }
    }

    Column {
        anchors.left: parent.left
        anchors.leftMargin: 22
        anchors.top: parent.top
        anchors.topMargin: 20
        spacing: 4

        Text {
            text: "PenguFoce"
            color: "#f3ece7"
            font.family: "Bahnschrift SemiCondensed"
            font.pixelSize: 28
            font.bold: true
        }

        Text {
            text: "ORBITAL CONTROL MESH"
            color: bladeSidebarBridge.textMutedColor
            font.family: "Bahnschrift SemiCondensed"
            font.pixelSize: 12
            font.letterSpacing: 1.8
        }
    }

    Rectangle {
        width: 42
        height: 34
        radius: 11
        anchors.top: parent.top
        anchors.topMargin: 96
        anchors.right: parent.right
        anchors.rightMargin: 22
        color: bladeSidebarBridge.canPageUp ? Qt.rgba(1, 1, 1, 0.07) : Qt.rgba(1, 1, 1, 0.03)
        border.width: 1
        border.color: bladeSidebarBridge.canPageUp ? Qt.rgba(1, 1, 1, 0.20) : Qt.rgba(1, 1, 1, 0.08)
        opacity: bladeSidebarBridge.canPageUp ? 1.0 : 0.45

        Text {
            anchors.centerIn: parent
            text: "\u25B2"
            color: "#f4f6fb"
            font.pixelSize: 12
            font.bold: true
        }

        MouseArea {
            anchors.fill: parent
            enabled: bladeSidebarBridge.canPageUp
            cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: bladeSidebarBridge.pageUp()
        }
    }

    Rectangle {
        width: 42
        height: 34
        radius: 11
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 24
        anchors.right: parent.right
        anchors.rightMargin: 22
        color: bladeSidebarBridge.canPageDown ? Qt.rgba(1, 1, 1, 0.07) : Qt.rgba(1, 1, 1, 0.03)
        border.width: 1
        border.color: bladeSidebarBridge.canPageDown ? Qt.rgba(1, 1, 1, 0.20) : Qt.rgba(1, 1, 1, 0.08)
        opacity: bladeSidebarBridge.canPageDown ? 1.0 : 0.45

        Text {
            anchors.centerIn: parent
            text: "\u25BC"
            color: "#f4f6fb"
            font.pixelSize: 12
            font.bold: true
        }

        MouseArea {
            anchors.fill: parent
            enabled: bladeSidebarBridge.canPageDown
            cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: bladeSidebarBridge.pageDown()
        }
    }

    Repeater {
        model: previousItems.length

        delegate: Item {
            property var item: root.previousItemAt(index)
            property point anchorPoint: root.frontAnchorForItem(item, true)
            visible: false
            anchors.fill: parent
        }
    }

    Repeater {
        model: frontItems.length

        delegate: Item {
            property var item: root.frontItemAt(index)
            property point anchorPoint: root.frontAnchorForItem(item, false)
            property real cardX: root.cardLeftForAnchor(anchorPoint.x)
            property real cardY: root.cardTopForAnchor(anchorPoint.y)
            property real orbitalAngle: root.currentFrontAngle(item)
            property real depth: root.depthForAngle(orbitalAngle)
            visible: item !== null
            anchors.fill: parent
            z: 40 + depth

            Item {
                x: anchorPoint.x - 16
                y: anchorPoint.y - 16
                width: 32
                height: 32
                scale: (root.transitionRunning ? (0.90 + (0.10 * root.transitionFade)) : 1.0)
                       * root.scaleForAngle(orbitalAngle, 0.88, 1.14)
                opacity: root.transitionFade

                Rectangle {
                    anchors.centerIn: parent
                    x: 2
                    y: 3
                    width: item && item.active ? 34 : 30
                    height: width
                    radius: width * 0.5
                    color: Qt.rgba(0.0, 0.0, 0.0, item && item.active ? 0.22 : 0.12)
                }

                Rectangle {
                    anchors.centerIn: parent
                    width: item && item.active ? 40 : 34
                    height: width
                    radius: width * 0.5
                    color: Qt.rgba(bladeSidebarBridge.accentColor.r, bladeSidebarBridge.accentColor.g, bladeSidebarBridge.accentColor.b, item && item.active ? 0.18 : 0.10)
                }

                Rectangle {
                    anchors.centerIn: parent
                    width: item && item.active ? 32 : 28
                    height: width
                    radius: width * 0.5
                    color: Qt.rgba(bladeSidebarBridge.accentColor.r, bladeSidebarBridge.accentColor.g, bladeSidebarBridge.accentColor.b, item && item.active ? 0.34 : 0.20)
                    border.width: 1
                    border.color: Qt.rgba(1, 1, 1, item && item.active ? 0.34 : 0.16)
                }

                Rectangle {
                    anchors.centerIn: parent
                    width: item && item.active ? 18 : 16
                    height: width
                    radius: width * 0.5
                    color: item && item.active ? "#fff5f8" : "#e2e8f2"
                    border.width: 1
                    border.color: Qt.rgba(1, 1, 1, 0.18)
                }

                Rectangle {
                    anchors.centerIn: parent
                    x: -2
                    y: -4
                    width: item && item.active ? 8 : 7
                    height: width
                    radius: width * 0.5
                    color: Qt.rgba(1, 1, 1, 0.38)
                }
            }

            Rectangle {
                x: anchorPoint.x + 12
                y: anchorPoint.y - 1
                width: Math.max(10, cardX - anchorPoint.x - 12)
                height: 2
                radius: 1
                color: Qt.rgba(bladeSidebarBridge.edgeGlowColor.r, bladeSidebarBridge.edgeGlowColor.g, bladeSidebarBridge.edgeGlowColor.b, item && item.active ? 0.34 : 0.18)
                opacity: 0.70 + (0.30 * root.transitionFade)
            }

            Item {
                x: cardX
                y: cardY
                width: root.cardWidth
                height: root.cardHeight
                scale: root.transitionRunning ? (0.965 + (0.035 * root.transitionFade)) : 1.0
                opacity: root.transitionFade
                z: 60 + depth

                Rectangle {
                    anchors.fill: parent
                    radius: 16
                    color: item && item.active
                        ? Qt.rgba(bladeSidebarBridge.accentColor.r, bladeSidebarBridge.accentColor.g, bladeSidebarBridge.accentColor.b, 0.72)
                        : Qt.rgba(1, 1, 1, 0.06)
                    border.width: 1
                    border.color: item && item.active ? Qt.rgba(1, 1, 1, 0.28) : Qt.rgba(1, 1, 1, 0.10)
                }

                Rectangle {
                    anchors.fill: parent
                    radius: 16
                    color: "transparent"
                    border.width: 1
                    border.color: Qt.rgba(1, 1, 1, 0.05 + (depth * 0.10))
                }

                Column {
                    anchors.left: parent.left
                    anchors.leftMargin: 11
                    anchors.right: parent.right
                    anchors.rightMargin: 11
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: 3

                    Text {
                        text: item ? item.name : ""
                        color: "#f7f8fb"
                        font.family: "Bahnschrift SemiCondensed"
                        font.pixelSize: item && item.active ? 14 : 13
                        font.bold: true
                        elide: Text.ElideRight
                    }

                    Text {
                        text: item ? item.description : ""
                        color: item && item.active ? "#f2d8df" : bladeSidebarBridge.textMutedColor
                        font.family: "Bahnschrift SemiCondensed"
                        font.pixelSize: 8
                        wrapMode: Text.WordWrap
                        maximumLineCount: 2
                        elide: Text.ElideRight
                    }
                }

                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: if (item) bladeSidebarBridge.selectOrb(item.index)
                }
            }
        }
    }
}
