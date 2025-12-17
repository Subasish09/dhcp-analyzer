// app.js
function fetchAndRender() {
  $.getJSON("/api/events", function (data) {
    $("#status").text("Events: " + data.length + " (updated " + new Date().toLocaleTimeString() + ")");
    const tbody = $("#events tbody");
    tbody.empty();
    const recent = data.slice(-200).reverse();
    const states = {}; // mac -> last type
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
      states[mac] = typ;
    });

    const csdom = $("#client-states");
    csdom.empty();
    for (const [mac, st] of Object.entries(states)) {
      const el = $("<div></div>").text(mac + " → " + st);
      csdom.append(el);
    }
  });
}

$(function () {
  fetchAndRender();
  setInterval(fetchAndRender, 1500);
});
