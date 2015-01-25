/*
 *    luaxuv: extended libuv binding for Lua 5.1 & LuaJIT
 *    by Zyxwvu Shi <imzyxwvu@gmail.com> @ 201501
 */

#include <stdlib.h>
#include <lua.h>
#include <lauxlib.h>
#include <uv.h>

static lua_State *L_Main = NULL;

typedef struct {
	uv_handle_t *data;
	const char *tname;
	int cbreadref, cbref, cbreadself, cbself;
} luaxuv_handle;

typedef struct {
	uv_handle_t *handle;
	int cb_close, cb_data, ref_self;
	int flags;
} luaxuv_stream;

typedef struct {
	uv_handle_t *handle;
	int cb_conn, ref_self, ref_loop;
} luaxuv_server;

typedef struct {
	int l_ref;
	luaxuv_stream *self;
} luaxuv_callback;

#define LXUV_MT_LOOP   "UV: Loop"
#define LXUV_MT_STREAM "UV: Stream"
#define LXUV_MT_SERVER "UV: Server"
#define LXUV_MT_HANDLE "UV: Handle"
#define LXUV_FLAG_USABLE  0x1
#define LXUV_FLAG_READING 0x1
#define LXUV_LUA_UNREF(v) if(v != LUA_REFNIL) { \
	luaL_unref(L, LUA_REGISTRYINDEX, v); \
	v = LUA_REFNIL; \
}

static void luaxuv_pushaddr(lua_State* L, struct sockaddr_storage* address, int addrlen)
{
	char ip[INET6_ADDRSTRLEN];
	int port = 0;
	if (address->ss_family == AF_INET) {
		struct sockaddr_in* addrin = (struct sockaddr_in*)address;
		uv_inet_ntop(AF_INET, &(addrin->sin_addr), ip, addrlen);
		port = ntohs(addrin->sin_port);
	} else if (address->ss_family == AF_INET6) {
		struct sockaddr_in6* addrin6 = (struct sockaddr_in6*)address;
		uv_inet_ntop(AF_INET6, &(addrin6->sin6_addr), ip, addrlen);
		port = ntohs(addrin6->sin6_port);
	}
	lua_pushstring(L, ip);
	lua_pushinteger(L, port);
}

static luaxuv_stream *luaxuv_pushstream(lua_State *L, uv_handle_t *handle)
{
	luaxuv_stream *self = lua_newuserdata(L, sizeof(luaxuv_stream));
	self->handle = handle;
	self->flags = 0;
	self->cb_close = self->cb_data = LUA_REFNIL;
	luaL_getmetatable(L, LXUV_MT_STREAM);
	lua_setmetatable(L, -2);
	lua_pushvalue(L, -1);
	self->ref_self = luaL_ref(L, LUA_REGISTRYINDEX);
	handle->data = self;
	return self;
}

static luaxuv_server *luaxuv_pushserver(lua_State *L, uv_handle_t *handle)
{
	luaxuv_server *self = lua_newuserdata(L, sizeof(luaxuv_server));
	self->handle = handle;
	luaL_getmetatable(L, LXUV_MT_SERVER);
	lua_setmetatable(L, -2);
	lua_pushvalue(L, -1);
	self->ref_self = luaL_ref(L, LUA_REGISTRYINDEX);
	handle->data = self;
	self->ref_loop = self->cb_conn = LUA_REFNIL;
	return self;
}

static int l_stream__newindex(lua_State *L)
{
	// assert(type(k) == "string")
	luaL_checktype(L, 2, LUA_TSTRING);
	// local f = setters[k]
	lua_pushvalue(L, 2);
	lua_rawget(L, lua_upvalueindex(1));
	// assert(type(f) == "function")
	if(!lua_isfunction(L, -1))
		return luaL_error(L, "no such setter or setter bad type");
	// f(self, v or nil)
	lua_pushvalue(L, 1);
	if(lua_isnoneornil(L, 3)) {
		lua_pushnil(L);
	} else {
		lua_pushvalue(L, 3);
	}
	lua_call(L, 2, 0);
	return 0;
}

static int l_stream_set_on_data(lua_State *L)
{
	luaxuv_stream *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
	if(NULL == self->handle)
		return luaL_error(L, "handle has been closed");
	if(self->flags & LXUV_FLAG_READING) {
		if(lua_isnoneornil(L, 2))
			return luaL_error(L, "reading handles must have a callback");
	}
	if(self->cb_data != LUA_REFNIL)
		luaL_unref(L, LUA_REGISTRYINDEX, self->cb_data);
	if(lua_isnoneornil(L, 2))
		self->cb_close = LUA_REFNIL;
	else {
		luaL_checktype(L, 2, LUA_TFUNCTION);
		lua_pushvalue(L, 2);
		self->cb_data = luaL_ref(L, LUA_REGISTRYINDEX);
	}
	return 0;
}

static int l_stream_set_on_close(lua_State *L)
{
	luaxuv_stream *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
	if(NULL == self->handle)
		return luaL_error(L, "handle has been closed");
	if(self->cb_close != LUA_REFNIL)
		luaL_unref(L, LUA_REGISTRYINDEX, self->cb_close);
	if(lua_isnoneornil(L, 2))
		self->cb_close = LUA_REFNIL;
	else {
		luaL_checktype(L, 2, LUA_TFUNCTION);
		lua_pushvalue(L, 2);
		self->cb_close = luaL_ref(L, LUA_REGISTRYINDEX);
	}
	return 0;
}

static void luaxuv_on_shutdown(uv_shutdown_t* req, int status)
{
	luaxuv_stream *self = req->data;
	lua_State *L = L_Main;
	uv_close((uv_handle_t *)req->handle, (uv_close_cb)free);
	free(req);
	LXUV_LUA_UNREF(self->cb_data);
	if(self->cb_close != LUA_REFNIL) {
		lua_rawgeti(L, LUA_REGISTRYINDEX, self->cb_close);
		luaL_unref(L, LUA_REGISTRYINDEX, self->cb_close);
		self->cb_close = LUA_REFNIL;
		lua_pushliteral(L, "over");
		lua_call(L, 1, 0);
	}
}

static int l_stream_close(lua_State *L)
{
	luaxuv_stream *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
	if(self->handle) {
		int directly_closing = 1;
		if(self->flags & LXUV_FLAG_USABLE) {
			uv_shutdown_t *req = malloc(sizeof(uv_shutdown_t));
			req->data = self;
			if(!req) { uv_close(self->handle, (uv_close_cb)free); } else
			if(uv_shutdown(req, (uv_stream_t *)self->handle, luaxuv_on_shutdown) < 0) {
				free(req);
				uv_close(self->handle, (uv_close_cb)free);
			}
			directly_closing = 0; // defer removing callbacks
		} else uv_close(self->handle, (uv_close_cb)free);
		self->handle = NULL; self->flags = 0;
		LXUV_LUA_UNREF(self->ref_self);
		if(directly_closing) {
			LXUV_LUA_UNREF(self->cb_data);
			if(self->cb_close != LUA_REFNIL) {
				int has_no_arg = lua_isnoneornil(L, 2);
				lua_rawgeti(L, LUA_REGISTRYINDEX, self->cb_close);
				luaL_unref(L, LUA_REGISTRYINDEX, self->cb_close);
				self->cb_close = LUA_REFNIL;
				if(has_no_arg) {
					lua_call(L, 0, 0);
				} else {
					lua_pushvalue(L, 2);
					lua_call(L, 1, 0);
				}
			}
		}
	}
	return 0;
}

static int l_stream__gc(lua_State *L)
{
	luaxuv_stream *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
	if(self->handle) {
		uv_close(self->handle, (uv_close_cb)free);
		fprintf(stderr, "xuv: forgot to close stream 0x%X\n", self->handle);
		self->handle = NULL;
	}
	return 0;
}

static void luaxuv_on_write(uv_write_t *req, int status)
{
	luaxuv_callback *cb = req->data;
	free(req);
	if(cb) {
		luaxuv_stream *self = cb->self;
		int cb_ref = cb->l_ref;
		free(cb);
		if(NULL == self->handle) return;
		lua_rawgeti(L_Main, LUA_REGISTRYINDEX, cb_ref);
		luaL_unref(L_Main, LUA_REGISTRYINDEX, cb_ref);
		if(status == 0) {
			lua_call(L_Main, 0, 0);
		} else {
			self->flags &= ~LXUV_FLAG_USABLE;
			// self:close(err)
			lua_pushcfunction(L_Main, l_stream_close);
			lua_rawgeti(L_Main, LUA_REGISTRYINDEX, self->ref_self);
			lua_pushstring(L_Main, uv_err_name(status));
			lua_call(L_Main, 2, 0);
			// callback(err)
			lua_pushstring(L_Main, uv_err_name(status));
			lua_call(L_Main, 1, 0);
		}
	}
}

static int l_stream_write(lua_State *L)
{
	luaxuv_stream *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
	uv_buf_t buf;
	uv_write_t *req;
	luaxuv_callback *cb = NULL;
	int r;
	if(NULL == self->handle)
		return luaL_error(L, "attempt to operate on a closed stream");
	if(!(self->flags & LXUV_FLAG_USABLE))
		return luaL_error(L, "stream is not open");
	// TODO: data to send must be a string currently, tables should be accepted
	buf.base = (char *) luaL_checklstring(L, 2, &buf.len);
	
	if(!lua_isnoneornil(L, 3)) {
		luaL_checktype(L, 3, LUA_TFUNCTION);
		lua_pushvalue(L, 3);
		cb = malloc(sizeof(luaxuv_callback));
		cb->l_ref = luaL_ref(L, LUA_REGISTRYINDEX);
		cb->self = self;
	}
	req = malloc(sizeof(*req));
	req->data = cb;
	r = uv_write(req, (uv_stream_t *)self->handle, &buf, 1, luaxuv_on_write);
	if(r < 0) {
		if(cb) {
			luaL_unref(L, LUA_REGISTRYINDEX, cb->l_ref);
			free(cb);
		}
		free(req);
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);
	}
	return 0;
}

static void luaxuv_on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
	buf->base = malloc(suggested_size);
	buf->len = buf->base ? suggested_size : 0;
}

static void luaxuv_on_data(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf) {
	luaxuv_stream *self = handle->data;
	if (nread > 0) {
		lua_rawgeti(L_Main, LUA_REGISTRYINDEX, self->cb_data);
		lua_pushlstring(L_Main, buf->base, nread);
		free(buf->base);
		lua_call(L_Main, 1, 0);
	} else {
		if(buf->base) free(buf->base);
		self->flags &= ~LXUV_FLAG_USABLE;
		if (nread == UV_EOF) {
			lua_pushcfunction(L_Main, l_stream_close);
			lua_rawgeti(L_Main, LUA_REGISTRYINDEX, self->ref_self);
			lua_call(L_Main, 1, 0);
		} else if(nread < 0) {
			lua_pushcfunction(L_Main, l_stream_close);
			lua_rawgeti(L_Main, LUA_REGISTRYINDEX, self->ref_self);
			lua_pushstring(L_Main, uv_err_name(nread));
			lua_call(L_Main, 2, 0);
		}
	}
}

static int l_stream_read_start(lua_State *L)
{
	luaxuv_stream *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
	int r;
	if(NULL == self->handle)
		return luaL_error(L, "attempt to operate on a closed stream");
	if(!(self->flags & LXUV_FLAG_USABLE))
		return luaL_error(L, "stream is not open");
	if(LUA_REFNIL == self->cb_data)
		return luaL_error(L, "first of all set a callback");
	r = uv_read_start((uv_stream_t *)self->handle, luaxuv_on_alloc, luaxuv_on_data);
	if(r < 0) {
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);
	}
	self->flags |= LXUV_FLAG_READING;
	return 0;
}

static int l_stream_read_stop(lua_State *L)
{
	luaxuv_stream *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
	int r;
	if(NULL == self->handle)
		return luaL_error(L, "attempt to operate on a closed stream");
	if(!(self->flags & LXUV_FLAG_USABLE))
		return luaL_error(L, "stream is not open");
	r = uv_read_stop((uv_stream_t *)self->handle);
	if(r < 0) {
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);
	}
	self->flags &= ~LXUV_FLAG_READING;
	return 0;
}

static int l_stream_getsockname(lua_State *L)
{
	luaxuv_stream *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
	int addrlen, r;
	struct sockaddr_storage address;
	if(NULL == self->handle)
		return luaL_error(L, "attempt to operate on a closed stream");
	if(UV_TCP != self->handle->type)
		return luaL_error(L, "stream is not a TCP stream");
	r = uv_tcp_getsockname(
		(uv_tcp_t *)self->handle,
		(struct sockaddr*)&address, &addrlen);
	if(r < 0) {
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);
	}
	luaxuv_pushaddr(L, &address, addrlen);
	return 2;
}

static int l_stream_getpeername(lua_State *L)
{
	luaxuv_stream *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
	int addrlen, r;
	struct sockaddr_storage address;
	if(NULL == self->handle)
		return luaL_error(L, "attempt to operate on a closed stream");
	if(UV_TCP != self->handle->type)
		return luaL_error(L, "stream is not a TCP stream");
	r = uv_tcp_getpeername(
		(uv_tcp_t *)self->handle,
		(struct sockaddr*)&address, &addrlen);
	if(r < 0) {
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);
	}
	luaxuv_pushaddr(L, &address, addrlen);
	return 2;
}

static int l_stream_nodelay(lua_State *L)
{
	luaxuv_stream *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
	int r;
	if(NULL == self->handle)
		return luaL_error(L, "attempt to operate on a closed stream");
	luaL_checktype(L, 2, LUA_TBOOLEAN);
	if(UV_TCP != self->handle->type)
		return luaL_error(L, "stream is not a TCP stream");
	r = uv_tcp_nodelay((uv_tcp_t *)self->handle, lua_toboolean(L, 2));
	if(r < 0) {
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);
	}
	return 0;
}

static void luaxuv_on_connect(uv_connect_t* req, int status)
{
	luaxuv_callback *cb = (luaxuv_callback *)req->data;
	luaxuv_stream *self = cb->self;
	int cb_ref = cb->l_ref;
	
	free(cb);
	free(req);
	if(NULL == self->handle) return;
	lua_rawgeti(L_Main, LUA_REGISTRYINDEX, cb_ref);
	luaL_unref(L_Main, LUA_REGISTRYINDEX, cb_ref);
	if(status == 0) {
		self->flags |= LXUV_FLAG_USABLE;
		lua_rawgeti(L_Main, LUA_REGISTRYINDEX, self->ref_self);
		lua_call(L_Main, 1, 0);
	} else {
		lua_pushcfunction(L_Main, l_stream_close);
		lua_rawgeti(L_Main, LUA_REGISTRYINDEX, self->ref_self);
		lua_call(L_Main, 1, 0);
		lua_pushnil(L_Main);
		lua_pushstring(L_Main, uv_err_name(status));
		lua_call(L_Main, 2, 0);
	}
}

static int l_tcp_connect(lua_State *L)
{
	uv_loop_t *g_loop = luaL_checkudata(L, lua_upvalueindex(1), LXUV_MT_LOOP);
	const char *ip = luaL_checkstring(L, 1);
	int port = luaL_checkinteger(L, 2);
	struct sockaddr_in addr;
	uv_tcp_t *stream;
	int r;

	if(uv_ip4_addr(ip, port, (struct sockaddr_in*)&addr) &&
	   uv_ip6_addr(ip, port, (struct sockaddr_in6*)&addr))
		return luaL_error(L, "invalid IP address or port");
	luaL_checktype(L, 3, LUA_TFUNCTION);
	if(stream = malloc(sizeof(*stream))) {
		r = uv_tcp_init(g_loop, stream);
		if(r < 0) {
			free(stream);
			lua_pushstring(L, uv_strerror(r));
			return lua_error(L);
		}
	} else return luaL_error(L, "can't allocate memory");
	{
		luaxuv_stream *self = luaxuv_pushstream(L, (uv_handle_t *)stream);
		uv_connect_t *req = malloc(sizeof(uv_connect_t));
		luaxuv_callback *cb = malloc(sizeof(luaxuv_callback));
		lua_pushvalue(L, 3);
		cb->l_ref = luaL_ref(L, LUA_REGISTRYINDEX);
		cb->self = self;
		req->data = cb;
		r = uv_tcp_connect(req, stream, (struct sockaddr *)&addr, luaxuv_on_connect);
		if(r < 0) {
			free(req);
			luaL_unref(L, LUA_REGISTRYINDEX, cb->l_ref);
			free(cb);
			lua_pushcfunction(L, l_stream_close);
			lua_pushvalue(L, -2);
			lua_call(L, 1, 0);
			lua_pushstring(L, uv_strerror(r));
			return lua_error(L);
		}
		return 1;
	}
}

static int l_pipe_connect(lua_State *L)
{
	uv_loop_t *g_loop = luaL_checkudata(L, lua_upvalueindex(1), LXUV_MT_LOOP);
	const char *name = luaL_checkstring(L, 1);
	int ipc = lua_toboolean(L, 2);
	uv_pipe_t *stream;
	int r;

	luaL_checktype(L, 3, LUA_TFUNCTION);
	if(stream = malloc(sizeof(*stream))) {
		r = uv_pipe_init(g_loop, stream, ipc);
		if(r < 0) {
			free(stream);
			lua_pushstring(L, uv_strerror(r));
			return lua_error(L);
		}
	} else return luaL_error(L, "can't allocate memory");
	{
		luaxuv_stream *self = luaxuv_pushstream(L, (uv_handle_t *)stream);
		uv_connect_t *req = malloc(sizeof(uv_connect_t));
		luaxuv_callback *cb = malloc(sizeof(luaxuv_callback));
		lua_pushvalue(L, 3);
		cb->l_ref = luaL_ref(L, LUA_REGISTRYINDEX);
		cb->self = self;
		req->data = cb;
		uv_pipe_connect(req, stream, name, luaxuv_on_connect);
		return 1;
	}
}

static luaL_Reg lreg_stream_newindex[] = {
	{ "on_data", l_stream_set_on_data },
	{ "on_close", l_stream_set_on_close },
	{ NULL, NULL }
};

static luaL_Reg lreg_stream_methods[] = {
	{ "getsockname", l_stream_getsockname },
	{ "getpeername", l_stream_getpeername },
	{ "nodelay", l_stream_nodelay },
	{ "read_start", l_stream_read_start },
	{ "read_stop", l_stream_read_stop },
	{ "close", l_stream_close },
	{ "write", l_stream_write },
	{ NULL, NULL }
};

static int l_server_close(lua_State *L)
{
	luaxuv_server *self = luaL_checkudata(L, 1, LXUV_MT_SERVER);
	if(self->handle) {
		uv_close(self->handle, (uv_close_cb)free);
		self->handle = NULL;
		LXUV_LUA_UNREF(self->ref_self);
		LXUV_LUA_UNREF(self->cb_conn);
		LXUV_LUA_UNREF(self->ref_loop);
	}
	return 0;
}

static void luaxuv_on_conn(uv_stream_t* handle, int status) {
	luaxuv_server *self = handle->data;
	if(status < 0) {
		lua_rawgeti(L_Main, LUA_REGISTRYINDEX, self->cb_conn);
		lua_pushnil(L_Main);
		lua_pushstring(L_Main, uv_err_name(status));
		lua_call(L_Main, 2, 0);
	} else {
		uv_loop_t *g_loop;
		uv_tcp_t *stream = malloc(sizeof(uv_tcp_t));
		int r;
		if(!stream) return;
		lua_rawgeti(L_Main, LUA_REGISTRYINDEX, self->ref_loop);
		g_loop = lua_touserdata(L_Main, -1);
		lua_pop(L_Main, 1);
		r = uv_tcp_init(g_loop, stream);
		if(r < 0) {
			free(stream);
			return;
		}
		r = uv_accept(handle, (uv_stream_t *)stream);
		if(r < 0) {
			uv_close((uv_handle_t *)stream, (uv_close_cb)free);
		} else {
			luaxuv_stream *client;
			lua_rawgeti(L_Main, LUA_REGISTRYINDEX, self->cb_conn);
			client = luaxuv_pushstream(L_Main, (uv_handle_t *)stream);
			client->flags |= LXUV_FLAG_USABLE;
			lua_call(L_Main, 1, 0);
		}
	}
}

static int l_listen(lua_State *L)
{
	uv_loop_t *g_loop = luaL_checkudata(L, lua_upvalueindex(1), LXUV_MT_LOOP);
	const char *ip = luaL_checkstring(L, 1);
	int port = luaL_checkinteger(L, 2);
	int backlog = luaL_checkinteger(L, 3);
	struct sockaddr_in addr;
	uv_tcp_t *stream;
	int r;

	if(uv_ip4_addr(ip, port, (struct sockaddr_in*)&addr) &&
	   uv_ip6_addr(ip, port, (struct sockaddr_in6*)&addr))
		return luaL_error(L, "invalid IP address or port");
	luaL_checktype(L, 4, LUA_TFUNCTION);
	if(stream = malloc(sizeof(*stream))) {
		r = uv_tcp_init(g_loop, stream);
		if(r < 0) {
			free(stream);
			lua_pushstring(L, uv_strerror(r));
			return lua_error(L);
		}
	} else return luaL_error(L, "can't allocate memory");
	r = uv_tcp_bind((uv_tcp_t *)stream, (struct sockaddr *)&addr, 0);
	if(r < 0) { 
		uv_close((uv_handle_t *)stream, (uv_close_cb)free);
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);	
	}
	{
		luaxuv_server *self = luaxuv_pushserver(L, (uv_handle_t *)stream);
		lua_pushvalue(L, 4);
		self->cb_conn = luaL_ref(L, LUA_REGISTRYINDEX);
		lua_pushvalue(L, lua_upvalueindex(1));
		self->ref_loop = luaL_ref(L, LUA_REGISTRYINDEX);
		r = uv_listen((uv_stream_t *)stream, backlog, luaxuv_on_conn);
		if(r < 0) { 
			lua_pushcfunction(L, l_server_close);
			lua_pushvalue(L, -2);
			lua_call(L, 1, 0);
			lua_pushstring(L, uv_strerror(r));
			return lua_error(L);	
		}
		return 1;
	}
}

static int l_run(lua_State *L)
{
	int r;
	uv_loop_t *g_loop = luaL_checkudata(L, lua_upvalueindex(1), LXUV_MT_LOOP);
	if(L_Main) return luaL_error(L, "calling uv.run in a callback");
	L_Main = L;
	r = uv_run(g_loop, UV_RUN_DEFAULT);
	L_Main = NULL;
	if(r < 0) {
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);
	}
	return 0;
}

static int l_run_nowait(lua_State *L)
{
	int r;
	uv_loop_t *g_loop = luaL_checkudata(L, lua_upvalueindex(1), LXUV_MT_LOOP);
	if(L_Main) return luaL_error(L, "calling uv.run_nowait in a callback");
	L_Main = L;
	r = uv_run(g_loop, UV_RUN_NOWAIT);
	L_Main = NULL;
	if(r < 0) {
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct {
	int cbref, cbself;
	luaxuv_handle *owner;
} luaZ_UVCallback;

static luaxuv_handle* luaxuv_newuvobj(lua_State *L, void *handle, const char *tn)
{
	luaxuv_handle *obj = lua_newuserdata(L, sizeof(luaxuv_handle));
	register int i;
	obj->data = handle;
	obj->tname = tn;
	obj->cbref = obj->cbreadref = LUA_REFNIL;
	obj->cbself = obj->cbreadself = LUA_REFNIL;
	luaL_getmetatable(L, LXUV_MT_HANDLE);
	lua_setmetatable(L, -2);
	return obj;
}

static luaZ_UVCallback* luaZ_newuvcb(lua_State *L, int idx, luaxuv_handle *obj)
{
	luaZ_UVCallback *cb = malloc(sizeof(luaZ_UVCallback));
	lua_pushvalue(L, idx);
	cb->cbref = luaL_ref(L, LUA_REGISTRYINDEX);
	lua_pushvalue(L, 1);
	cb->cbself = luaL_ref(L, LUA_REGISTRYINDEX);
	cb->owner = obj;
	return cb;
}

static void luaZ_freeuvcb(luaZ_UVCallback *cb)
{
	luaL_unref(L_Main, LUA_REGISTRYINDEX, cb->cbref);
	luaL_unref(L_Main, LUA_REGISTRYINDEX, cb->cbself);
	free(cb);
}

static void luaZ_checkuvcb(luaZ_UVCallback *cb)
{
	lua_rawgeti(L_Main, LUA_REGISTRYINDEX, cb->cbref);
	luaZ_freeuvcb(cb);
}

static int luaxuv_close(lua_State *L)
{
	luaxuv_handle *obj = luaL_checkudata(L, 1, LXUV_MT_HANDLE);
	if(obj->data) {
		uv_close(obj->data, (uv_close_cb)free);
		if(obj->cbreadref != LUA_REFNIL) {
			luaL_unref(L, LUA_REGISTRYINDEX, obj->cbreadref);
			luaL_unref(L, LUA_REGISTRYINDEX, obj->cbreadself);
		}
		if(obj->cbref != LUA_REFNIL) {
			luaL_unref(L, LUA_REGISTRYINDEX, obj->cbref);
			luaL_unref(L, LUA_REGISTRYINDEX, obj->cbself);
		}
		obj->cbref = obj->cbreadref = LUA_REFNIL;
		obj->cbself = obj->cbreadself = LUA_REFNIL;
		obj->data = NULL;
	}
	return 0;
}

static int luaxuv_handle_tostring(lua_State *L)
{
	luaxuv_handle *obj = luaL_checkudata(L, 1, LXUV_MT_HANDLE);
	lua_pushstring(L, obj->tname);
	return 1;
}

static int luaxuv_handle_len(lua_State *L) // This returns if the handle is closed
{
	luaxuv_handle *obj = luaL_checkudata(L, 1, LXUV_MT_HANDLE);
	lua_pushboolean(L, obj->data ? 1 : 0);
	return 1;
}

static luaL_Reg lreg_handle[] = {
	{ "__len", luaxuv_handle_len },
	{ "__gc", luaxuv_close },
	{ "__tostring", luaxuv_handle_tostring },
	{ NULL, NULL }
};

#define luaxuv_CHECK_CLOSED(obj) \
	if(!obj->data) luaL_error(L, "using a closed %s", obj->tname);

static int luaxuv_udp_new(lua_State *L)
{
	uv_loop_t *g_loop = luaL_checkudata(L, lua_upvalueindex(1), LXUV_MT_LOOP);
	uv_udp_t *handle = malloc(sizeof(uv_udp_t));
	register int r = uv_udp_init(g_loop, handle);
	if(r < 0) {
		free(handle);
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);
	}
	handle->data = luaxuv_newuvobj(L, handle, "UDP");
	return 1;
}

static void luaxuv_on_send(uv_udp_send_t* req, int status)
{
	if(req->data) {
		luaZ_checkuvcb(req->data);
		if(status == 0) {
			lua_pushnil(L_Main);
		} else {
			lua_pushstring(L_Main, uv_err_name(status));
		}
		free(req);
		lua_call(L_Main, 1, 0);
	} else free(req);
}

static int luaxuv_udp_send(lua_State *L)
{
	luaxuv_handle *obj = luaL_checkudata(L, 1, LXUV_MT_HANDLE);
	uv_buf_t buf;
	register int r;
	uv_udp_send_t *req;
	const char *ip;
	int port;
	struct sockaddr_storage addr;
	
	luaxuv_CHECK_CLOSED(obj);
	if(UV_UDP != obj->data->type)
		luaL_error(L, "expected a UDP handle, got %s", obj->tname);
	buf.base = (char*) luaL_checklstring(L, 2, &buf.len);
	ip = luaL_checkstring(L, 3);
	port = luaL_checkint(L, 4);
	if(uv_ip4_addr(ip, port, (struct sockaddr_in*)&addr) &&
	   uv_ip6_addr(ip, port, (struct sockaddr_in6*)&addr))
		return luaL_error(L, "invalid IP address or port");
	req = malloc(sizeof(*req));
	if(lua_isfunction(L, 5)) {
		req->data = luaZ_newuvcb(L, 5, obj);
	} else {
		req->data = NULL;
	}
	r = uv_udp_send(req, (uv_udp_t *)obj->data, &buf, 1, (struct sockaddr *)&addr, luaxuv_on_send);
	if(r < 0) {
		if(req->data) luaZ_freeuvcb(req->data);
		free(req);
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);
	}
	return 0;
}

static int luaxuv_udp_bind(lua_State *L)
{
	luaxuv_handle *obj = luaL_checkudata(L, 1, LXUV_MT_HANDLE);
	const char *ip = luaL_checkstring(L, 2);
	int port = luaL_checkint(L, 3);
	register int r;
	struct sockaddr_storage addr;
	
	luaxuv_CHECK_CLOSED(obj);
	if(UV_UDP != obj->data->type)
		luaL_error(L, "expected a UDP handle, got %s", obj->tname);
	if(uv_ip4_addr(ip, port, (struct sockaddr_in*)&addr) &&
	   uv_ip6_addr(ip, port, (struct sockaddr_in6*)&addr))
		return luaL_error(L, "invalid IP address or port");
	r = uv_udp_bind((uv_udp_t *)obj->data, (struct sockaddr *)&addr, 0);
	if(r < 0) {
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);
	}
	return 0;
}

static void luaxuv_on_recv(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags) {
	luaxuv_handle *obj = handle->data;
	if(nread == 0) { free(buf->base); return; }
	lua_rawgeti(L_Main, LUA_REGISTRYINDEX, obj->cbreadref);
	if (nread >= 0) {
		lua_pushlstring(L_Main, buf->base, nread);
		free(buf->base);
		luaxuv_pushaddr(L_Main, (struct sockaddr_storage*)addr, sizeof(*addr));
		lua_call(L_Main, 3, 0);
	} else {
		free(buf->base);
		lua_pushnil(L_Main);
		lua_pushstring(L_Main, uv_err_name(nread));
		lua_call(L_Main, 2, 0);
	}
}

static int luaxuv_udp_recv_start(lua_State *L)
{
	luaxuv_handle *obj = luaL_checkudata(L, 1, LXUV_MT_HANDLE);
	register int r;

	luaxuv_CHECK_CLOSED(obj);
	if(UV_UDP != obj->data->type)
		luaL_error(L, "expected a UDP handle, got %s", obj->tname);
	luaL_checktype(L, 2, LUA_TFUNCTION);
	if(obj->cbreadref == LUA_REFNIL) {
		lua_pushvalue(L, 2);
		obj->cbreadref = luaL_ref(L, LUA_REGISTRYINDEX);
		lua_pushvalue(L, 1);
		obj->cbreadself = luaL_ref(L, LUA_REGISTRYINDEX);
		r = uv_udp_recv_start((uv_udp_t *)obj->data, luaxuv_on_alloc, luaxuv_on_recv);
		if(r < 0) {
			luaL_unref(L, LUA_REGISTRYINDEX, obj->cbreadref);
			luaL_unref(L, LUA_REGISTRYINDEX, obj->cbreadself);
			obj->cbreadself = obj->cbreadref = LUA_REFNIL;
			lua_pushstring(L, uv_strerror(r));
			return lua_error(L);
		}
	} else {
		luaL_unref(L, LUA_REGISTRYINDEX, obj->cbreadref);
		lua_pushvalue(L, 2);
		obj->cbreadref = luaL_ref(L, LUA_REGISTRYINDEX);
	}
	return 0;
}

static int luaxuv_udp_recv_stop(lua_State *L)
{
	luaxuv_handle *obj = luaL_checkudata(L, 1, LXUV_MT_HANDLE);
	register int r;
	
	luaxuv_CHECK_CLOSED(obj);
	if(UV_UDP != obj->data->type)
		luaL_error(L, "expected a UDP handle, got %s", obj->tname);
	if(obj->cbreadref == LUA_REFNIL) return 0;
	luaL_unref(L, LUA_REGISTRYINDEX, obj->cbreadref);
	luaL_unref(L, LUA_REGISTRYINDEX, obj->cbreadself);
	obj->cbreadself = obj->cbreadref = LUA_REFNIL;
	r = uv_udp_recv_stop((uv_udp_t *)obj->data);
	if(r < 0) {
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);
	}
	return 0;
}

static int luaxuv_timer_new(lua_State *L)
{
	uv_loop_t *g_loop = luaL_checkudata(L, lua_upvalueindex(1), LXUV_MT_LOOP);
	uv_timer_t *handle = malloc(sizeof(uv_timer_t));
	register int r = uv_timer_init(g_loop, handle);
	if(r < 0) {
		free(handle);
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);
	}
	handle->data = luaxuv_newuvobj(L, handle, "Timer");
	return 1;
}

static void luaxuv_on_timer(uv_timer_t* handle) {
	luaxuv_handle *obj = handle->data;
	lua_rawgeti(L_Main, LUA_REGISTRYINDEX, obj->cbref);
	lua_call(L_Main, 0, 0);
}

static int luaxuv_timer_start(lua_State *L)
{
	luaxuv_handle *obj = luaL_checkudata(L, 1, LXUV_MT_HANDLE);
	register int r;
	int timeout, repeat;
	
	luaxuv_CHECK_CLOSED(obj);
	if(UV_TIMER != obj->data->type)
		luaL_error(L, "expected a Timer handle, got %s", obj->tname);
	luaL_checktype(L, 2, LUA_TFUNCTION);
	timeout = luaL_checkint(L, 3);
	repeat = luaL_optint(L, 4, 0);
	if(obj->cbref != LUA_REFNIL) {
		luaL_unref(L, LUA_REGISTRYINDEX, obj->cbref);
		luaL_unref(L, LUA_REGISTRYINDEX, obj->cbself);
	}
	lua_pushvalue(L, 2);
	obj->cbref = luaL_ref(L, LUA_REGISTRYINDEX);
	lua_pushvalue(L, 1);
	obj->cbself = luaL_ref(L, LUA_REGISTRYINDEX);
	
	r = uv_timer_start((uv_timer_t *)obj->data, luaxuv_on_timer, timeout, repeat);
	if(r < 0) {
		luaL_unref(L, LUA_REGISTRYINDEX, obj->cbref);
		luaL_unref(L, LUA_REGISTRYINDEX, obj->cbself);
		obj->cbself = obj->cbref = LUA_REFNIL;
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);
	}
	return 0;
}

static int luaxuv_timer_stop(lua_State *L)
{
	luaxuv_handle *obj = luaL_checkudata(L, 1, LXUV_MT_HANDLE);
	register int r;
	
	luaxuv_CHECK_CLOSED(obj);
	if(UV_TIMER != obj->data->type)
		luaL_error(L, "expected a Timer handle, got %s", obj->tname);
	if(obj->cbref == LUA_REFNIL) return 0;
	luaL_unref(L, LUA_REGISTRYINDEX, obj->cbref);
	luaL_unref(L, LUA_REGISTRYINDEX, obj->cbself);
	obj->cbself = obj->cbref = LUA_REFNIL;
	r = uv_timer_stop((uv_timer_t *)obj->data);
	if(r < 0) {
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);
	}
	return 0;
}

static int luaxuv_timer_set_repeat(lua_State *L)
{
	luaxuv_handle *obj = luaL_checkudata(L, 1, LXUV_MT_HANDLE);
	
	luaxuv_CHECK_CLOSED(obj);
	if(UV_TIMER != obj->data->type)
		luaL_error(L, "expected a Timer handle, got %s", obj->tname);
	
	uv_timer_set_repeat((uv_timer_t *)obj->data, luaL_checkint(L, 2));
	return 0;
}

static int luaxuv_timer_get_repeat(lua_State *L)
{
	luaxuv_handle *obj = luaL_checkudata(L, 1, LXUV_MT_HANDLE);
	register int r;
	
	luaxuv_CHECK_CLOSED(obj);
	if(UV_TIMER != obj->data->type)
		luaL_error(L, "expected a Timer handle, got %s", obj->tname);
	
	lua_pushinteger(L, uv_timer_get_repeat((uv_timer_t *)obj->data));
	return 1;
}

static int luaxuv_cpu_info(lua_State* L) {
	uv_cpu_info_t* cpu_infos;
	int count, i;
	int ret = uv_cpu_info(&cpu_infos, &count);
	if (ret < 0) {
		lua_pushstring(L, uv_strerror(ret));
		return lua_error(L);
	}
	lua_newtable(L);
	for (i = 0; i < count; i++) {
		lua_newtable(L);
		lua_pushstring(L, cpu_infos[i].model);
		lua_setfield(L, -2, "model");
		lua_pushnumber(L, cpu_infos[i].speed);
		lua_setfield(L, -2, "speed");
		lua_newtable(L);
		lua_pushnumber(L, cpu_infos[i].cpu_times.user);
		lua_setfield(L, -2, "user");
		lua_pushnumber(L, cpu_infos[i].cpu_times.nice);
		lua_setfield(L, -2, "nice");
		lua_pushnumber(L, cpu_infos[i].cpu_times.sys);
		lua_setfield(L, -2, "sys");
		lua_pushnumber(L, cpu_infos[i].cpu_times.idle);
		lua_setfield(L, -2, "idle");
		lua_pushnumber(L, cpu_infos[i].cpu_times.irq);
		lua_setfield(L, -2, "irq");
		lua_setfield(L, -2, "times");
		lua_rawseti(L, -2, i + 1);
	}
	uv_free_cpu_info(cpu_infos, count);
	return 1;
}

static int luaxuv_get_total_memory(lua_State* L) {
	lua_pushnumber(L, uv_get_total_memory());
	return 1;
}

static int luaxuv_version_string(lua_State* L) {
	lua_pushstring(L, uv_version_string());
	return 1;
}

static int luaxuv_hrtime(lua_State* L) {
	lua_pushinteger(L, uv_hrtime());
	return 1;
}

static int luaxuv_update_time(lua_State* L) {
	uv_loop_t *g_loop = luaL_checkudata(L, lua_upvalueindex(1), LXUV_MT_LOOP);
	uv_update_time(g_loop);
	return 0;
}

static int luaxuv_set_process_title(lua_State* L) {
	const char* title = luaL_checkstring(L, 1);
	register int r = uv_set_process_title(title);
	if(r < 0)  {
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);
	}
	return 0;
}

static int luaxuv_kill(lua_State* L) {
	int pid = luaL_checkinteger(L, 1);
	int signum = luaL_optinteger(L, 2, SIGTERM);
	register int r = uv_kill(pid, signum);
	if(r < 0) {
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);
	}
	return 0;
}

static int luaxuv_uptime(lua_State* L) {
	double uptime;
	register int r = uv_uptime(&uptime);
	if(r < 0) {
		lua_pushstring(L, uv_strerror(r));
		return lua_error(L);
	}
	lua_pushnumber(L, uptime);
	return 1;
}

static luaL_Reg lreg_main[] = {
	{ "connect", l_tcp_connect },
	{ "tcp_connect", l_tcp_connect },
	{ "pipe_connect", l_pipe_connect },
	{ "listen", l_listen },
	{ "run", l_run },
	{ "run_nowait", l_run_nowait },
	{ "new_udp", luaxuv_udp_new },
	{ "new_timer", luaxuv_timer_new },
	{ "udp_new", luaxuv_udp_new },
	{ "udp_bind", luaxuv_udp_bind },
	{ "udp_send", luaxuv_udp_send },
	{ "udp_recv_start", luaxuv_udp_recv_start },
	{ "udp_recv_stop", luaxuv_udp_recv_stop },
	{ "timer_new", luaxuv_timer_new },
	{ "timer_start", luaxuv_timer_start },
	{ "timer_stop", luaxuv_timer_stop },
	{ "timer_get_repeat", luaxuv_timer_get_repeat },
	{ "timer_set_repeat", luaxuv_timer_set_repeat },
	{ "close", luaxuv_close },
	{ "kill", luaxuv_kill },
	{ "uptime", luaxuv_uptime },
	{ "hrtime", luaxuv_hrtime },
	{ "update_time", luaxuv_uptime },
	{ "cpu_info", luaxuv_cpu_info },
	{ "version_string", luaxuv_version_string },
	{ "get_total_memory", luaxuv_get_total_memory },
	{ "set_process_title", luaxuv_set_process_title },
	{ NULL, NULL }
};

static int l_loop__gc(lua_State *L)
{
	uv_loop_t *loop = luaL_checkudata(L, 1, LXUV_MT_LOOP);
	if(uv_loop_close(loop) < 0) {
		return luaL_error(L, "cannot close the uv_loop_t");
	}
	return 0;
}

LUA_API int luaopen_xuv(lua_State *L)
{
	uv_loop_t *g_loop = lua_newuserdata(L, sizeof(uv_loop_t));
	/* Initialize the libUV loop */ {
		int r = uv_loop_init(g_loop);
		if(r < 0) {
			lua_pushstring(L, uv_strerror(r));
			return lua_error(L);
		}
		luaL_newmetatable(L, LXUV_MT_LOOP);
		lua_pushcfunction(L, l_loop__gc);
		lua_setfield(L, -2, "__gc");
		lua_setmetatable(L, -2);
	}
	
	luaL_newmetatable(L, LXUV_MT_STREAM);
	lua_newtable(L);
	luaL_register(L, NULL, lreg_stream_newindex);
	lua_pushcclosure(L, l_stream__newindex, 1);
	lua_setfield(L, -2, "__newindex");
	lua_newtable(L);
	luaL_register(L, NULL, lreg_stream_methods);
	lua_setfield(L, -2, "__index");
	lua_pushcfunction(L, l_stream__gc);
	lua_setfield(L, -2, "__gc");
	
	luaL_newmetatable(L, LXUV_MT_SERVER);
	lua_newtable(L);
	lua_pushcfunction(L, l_server_close);
	lua_setfield(L, -2, "close");
	lua_setfield(L, -2, "__index");
	lua_pushcfunction(L, l_server_close);
	lua_setfield(L, -2, "__gc");
	
	luaL_newmetatable(L, LXUV_MT_HANDLE);
	luaL_register(L, NULL, lreg_handle);
	
	lua_pop(L, 3);
	lua_newtable(L);
	/* register the library functions */ {
		int i = 0;
		while(lreg_main[i].name && lreg_main[i].func) {
			lua_pushvalue(L, -2);
			lua_pushcclosure(L, lreg_main[i].func, 1);
			lua_setfield(L, -2, lreg_main[i].name);
			i++;
		}
	}
	return 1;
}