from __future__ import annotations


def method_tracer_script(class_name: str, method_name: str | None = None) -> str:
    m = method_name or "*"
    return f"""
Java.perform(function() {{
  try {{
    var cls = Java.use('{class_name}');
    var methods = cls.class.getDeclaredMethods();
    send('Tracing {class_name} methods: {m}');
    for (var i = 0; i < methods.length; i++) {{
      var name = methods[i].getName();
      if ('{m}' !== '*' && name !== '{m}') continue;
      try {{
        cls[name].overloads.forEach(function(ov) {{
          ov.implementation = function() {{
            send('CALL {class_name}.' + name);
            return ov.apply(this, arguments);
          }};
        }});
      }} catch (e) {{}}
    }}
  }} catch (e) {{
    send('Trace error: ' + e);
  }}
}});
""".strip()

