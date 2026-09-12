import QtQuick
import Quickshell.Io
import Quickshell.Services.Pipewire

Item {
  id: root

  property var lastExitCode: null
  property string lastError: ""
  property bool ready: false
  readonly property string serviceVersion: "0.3.0"

  // The isolated supervisor owns discovery and its entire process group.
  // A lost shell lease tears down the group without restarting shared audio.
  Process {
    id: discovery
    command: ["/usr/bin/python3", "-I",
      decodeURIComponent(Qt.resolvedUrl("omarchyair.py").toString().replace(/^file:\/\//, "")),
      "discover"]
    clearEnvironment: true
    // With clearEnvironment, null inherits this one variable instead of removing it.
    environment: ({ LC_ALL: "C", WAYLAND_DISPLAY: null })
    workingDirectory: "/"
    stdinEnabled: true
    running: true
    onStarted: discovery.write(".\n")
    stdout: SplitParser {
      onRead: function(data) {
        if (data === '{"ready":true}') root.ready = true
        else {
          root.lastError = "Invalid supervisor response"
          discovery.running = false
        }
      }
    }
    stderr: SplitParser {
      onRead: function(data) { root.lastError = data.substring(0, 1024) }
    }
    onExited: function(exitCode) {
      root.ready = false
      root.lastExitCode = exitCode
    }
  }

  Timer {
    interval: 5000
    repeat: true
    running: discovery.running
    onTriggered: discovery.write(".\n")
  }

  Component.onDestruction: discovery.running = false

  IpcHandler {
    target: "omarchyair"

    function status(): string {
      var receivers = []
      var nodes = Pipewire.nodes ? Pipewire.nodes.values : []
      for (var i = 0; i < nodes.length; i++) {
        var node = nodes[i]
        if (node.isSink && !node.isStream && String(node.name).indexOf("raop_sink.") === 0)
          receivers.push({ name: node.name, description: node.description,
            selected: node === Pipewire.defaultAudioSink })
      }
      return JSON.stringify({ ready: discovery.running && root.ready, version: root.serviceVersion,
        lastExitCode: root.lastExitCode, lastError: root.lastError,
        receivers: receivers })
    }
  }
}
