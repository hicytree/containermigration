from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime

class TimeServer(BaseHTTPRequestHandler):
    # Initialize counter
    counter = 0

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Increment counter
        TimeServer.counter += 1
        
        # Include counter in the response
        response = f'{current_time} (Counter: {TimeServer.counter})\n'
        self.wfile.write(response.encode())

def run(server_class=HTTPServer, handler_class=TimeServer, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting server on port {port}...')
    httpd.serve_forever()

if __name__ == '__main__':
    run()