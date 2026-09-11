import QtQuick
import Quickshell.Io
import Quickshell.Services.Pipewire

Item {
  id: root

  property var lastExitCode: null
  property string lastError: ""

  // The child owns its RAOP modules. Disabling this service removes its sinks
  // without editing PipeWire configuration or restarting the user's audio.
  Process {
    id: discovery
    command: ["pw-cli", "-m", "load-module", "libpipewire-module-raop-discover",
      '{ stream.rules = [ { matches = [ { raop.ip = "~.*" } ] actions = { create-stream = { stream.props = { priority.session = 0 } } } } ] }']
    running: true
    stdout: SplitParser {
      onRead: function(data) { console.log("Omarchy Air: " + data) }
    }
    stderr: SplitParser {
      onRead: function(data) {
        root.lastError = data
        console.warn("Omarchy Air: " + data)
        // pw-cli monitor mode otherwise stays alive after a failed command.
        if (data.indexOf("Error:") === 0) discovery.running = false
      }
    }
    onExited: function(exitCode) { root.lastExitCode = exitCode }
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
      return JSON.stringify({ running: discovery.running,
        lastExitCode: root.lastExitCode, lastError: root.lastError,
        receivers: receivers })
    }
  }
}
