# lua-xuv

This is a libuv binding for Lua focused on programmer happy! This meant that I have simplified lots of libuv APIs to make it easy to use in Lua. For example, we can create a TCP server that sends "Hello World" to clients in just the following code.

	-- Example 1
	uv = require "xuv"

	uv.listen("127.0.0.1", 23333, 32, function(client)
		client:write("Hello World!", function()
			client:close()
		end)
	end)

	uv.connect("127.0.0.1", 23333, function(self)
		function self.on_close()
			print("She closed the connection!")
		end
		function self.on_data(chunk)
			print("GOT:", chunk)
		end
		self:read_start()
	end)

	uv.run()

It is also OK to use it with SDL in your games to talk with your server:

	-- Example 2 - part code, imagine you have a Game library
	uv.connect("server_ip", server_port, function(self)
		self:nodelay(true) -- better sync meant better game experience
		local buffer = ""
		function self.on_data(chunk)
			buffer = buffer .. chunk -- store the data chunk into the buffer
			local n = buffer:find("\n", 1, true) -- has there been a complete line?
			if n then
				local line = buffer:sub(1, n - 1) -- check out the line
				buffer:sub(n + 1, -1) -- and leave the rest in the buffer
				Game.handleServerPacket(cjson.decode(line)) -- update the game
			end
		end
		self:read_start()
	end)

	--- The Main Loop of Your Game! ---
	while Game.running do
		Game.dispatchEvent(SDL.PollEvent()) -- collect joystick status...
		uv.run_nowait() -- also collect server updates...
		Game.update() -- think how the world goes...
		Game.render() -- draw the world onto the screen!
	end
    
Well, you ask me why I made the binding like this? Ruby inspired me. Let us have a look at the connect part of Example 1 again in Ruby:

	-- part of Example 1, but in Ruby
	uv.connect("127.0.0.1", 23333) do | self |
		def self.on_close
			print("She closed the connection!")
		end
		def self.on_data(chunk)
			print("GOT:", chunk)
		end
		self.read_start
	end

Yes, I translated the code into Ruby so smoothly because I took the ideas of Ruby's code blocks and instance methods. Ruby has lots of features for programmer happy!

## Work Better with Streams

The library is very easy-to-use but reading data from streams seems to be annoying. (for example, Example 2) So I'm working on a reader middleware for this library and I'll provide you later after I am sure it worked well.

Reader is a middleware and also a design which tooks advantages of Lua co-routines and helps programmers extract structured data (which is more widely used in dynamic programming) from streams (a series of chars) with another design called decoders.

	-- Example 3
	uv.listen("0.0.0.0", 80, Reader(function(reader)
		local request = reader:read "HTTP Request" -- HTTP Request is a decoder I'll provide with this project later
		if request.resource ## "/" then
			client.write "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello World!"
		else
			client.write "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nOops! Wrong way."
		end
		client.close() -- we didn't implement keep-alive connections. close the connection to notice that the document is over.
	end))
 
## Streams and Servers

### uv.tcp_connect("ip", port, callback) also called uv.connect

Try to connect to ip:port. If succeeded, callback will be called with the stream object. Otherwise, callback will be called with nil plus the error name.

Want to cancel the request before the callback is called? Remember the return value (also the stream object). When you want to do that, close it.

### uv.pipe_connect("/tmp/pipe.sock", false, callback)

Try to connect to the UNIX domain socket. Behaviors are just like uv.tcp_connect.

### uv.listen("ip", port, backlog, callback)

Listen the port. If we can't bind it, an error will be thrown. callback will be called with a stream object.

It returns a server object, so you can stop listening the port by calling server:close() whenever you want.

### stream:read_start() and stream:read_stop()

You can only call stream:read_start() when you have set an on_data callback. And the on_data callback can't be removed until you called stream:read_stop().

### stream:write(chunk[, callback]) and write_callback(err)

Write chunk to the stream. If there is a callback, you can know when the write request is done and if it is successful.

### stream:nodelay(true or false), stream:getpeername() and stream:getsockname()

Just do what their names hints. If you try to do these things with a pipe stream, an error will be thrown.

### stream:close([note])

Close the stream. It will shutdown the stream at first if needed. The on_close callback will be called later.

### stream.on_data(chunk)

Will be called when there is data available. And won't be called if there is an error. To catch the error, use the on_close callback.

This callback might be called after stream:close() if stream:close() does shutdown.

### stream.on_close([note])

Will be called when there is no more data or the stream is not writable any more. stream:close() will also call this.

If stream:close() does shutdown, note will be "over" instead of what you passed to stream:close().
 
## If You Want to Contribute

Just use it in your projects. If you found bugs, require some APIs I haven't bound or have any question, please feel free to open an issue!
 
## See also

[luvit/luv] luv is a bare libuv binding that tries to bind libuv as-is.