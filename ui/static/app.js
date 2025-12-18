// app.js

function fetchAndRender() {
  $.getJSON("/api/events", function (data) {
    $("#status").text(
      "Events: " + data.length + " (updated " + new Date().toLocaleTimeString() + ")"
    );

    const tbody = $("#events tbody");
    tbody.empty();

    const recent = data.slice(-200).reverse();
    const states = {}; // mac -> last DHCP state

    recent.forEach(ev => {
      const t = ev.ts || "";
      const hostname = ev.hostname || "-";
      const mac = ev.mac || "";
      const typ = (ev.dhcp_type || "").toUpperCase();
      const xid = ev.xid || "";
      const yi = ev.yiaddr || "";

      const tr = $("<tr></tr>");
      tr.append($("<td></td>").text(t));
      tr.append($("<td></td>").text(hostname));
      tr.append($("<td></td>").text(mac));
      tr.append($("<td></td>").text(typ));
      tr.append($("<td></td>").text(xid));
      tr.append($("<td></td>").text(yi));

      tbody.append(tr);

      if (mac) {
        states[mac] = typ;
      }
    });

    // Optional client state summary
    const csdom = $("#client-states");
    csdom.empty();

    for (const [mac, st] of Object.entries(states)) {
      const el = $("<div></div>").text(mac + " → " + st);
      csdom.append(el);
    }
  });
}


function fetchDevices() {
  fetch("/api/devices")   // ✅ FIXED ENDPOINT
    .then(res => res.json())
    .then(data => {
      const tbody = $("#devices tbody");
      tbody.empty();

      data.forEach(d => {
        const tr = $("<tr></tr>");
        tr.append($("<td></td>").text(d.ip));
        tr.append($("<td></td>").text(d.mac));
        tr.append($("<td></td>").text(d.hostname));
        tr.append($("<td></td>").text(d.vendor));
        tr.append($("<td></td>").text(d.last_seen + " sec ago"));
        tbody.append(tr);
      });
    })
    .catch(err => {
      console.error("Failed to fetch devices:", err);
    });
}


$(function () {
  fetchAndRender();
  fetchDevices();

  setInterval(fetchAndRender, 1500);
  setInterval(fetchDevices, 2000);
});
