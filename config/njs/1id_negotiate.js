/* 1id.com -- nginx NJS content negotiation module
   Routes root path (/) based on Accept header:
   - application/json  -> /.well-known/1id.json  (machine metadata)
   - text/markdown     -> /enroll.md             (agent enrollment instructions)
   - anything else     -> /index.html            (human homepage)

   Deploy to: /etc/nginx/njs/1id_negotiate.js
   Reference in nginx conf: js_import 1id_negotiate from /etc/nginx/njs/1id_negotiate.js; */

function handle_root_path_content_negotiation(request) {
  var accept_header_value = request.headersIn['Accept'] || 'text/html';

  if (accept_header_value.indexOf('application/json') !== -1) {
    request.internalRedirect('/.well-known/1id.json');
  } else if (accept_header_value.indexOf('text/markdown') !== -1) {
    request.internalRedirect('/enroll.md');
  } else {
    request.internalRedirect('/index.html');
  }
}

export default { handle_root_path_content_negotiation };
