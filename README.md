# gtox
## intro
Yet another simple and light-weight go binding for toxcore.

The echo-bot example will be a good tutorial on how to use this lib.

And of course, issues and prs are welcome.

## binding detail
### naming style
1. Xxxx_xxxx_xx for types, funcs
2. `tox_`, `_get` was stripped from the original name

### the unsupported
what c-api/type wont be added:
1. type Loglevel , tox_log_cb
2. log_user_data , log_callback in Tox_Options

### the unexported
what c-api/type wont be exported:
1. all error type(error is processed in bindings by return one more `error` argument)
2. type Loglevel , tox_log_cb
3. log_user_data , log_callback in Tox_Options
4. tox_options_set* , tox_options_get*(replaced by a wrapper struct which could access directly)
