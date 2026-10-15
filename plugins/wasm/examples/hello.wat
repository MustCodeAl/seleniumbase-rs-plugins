(module
  (memory (export "memory") 1)

  ;; The strings the host reads: a JSON string and a JSON array.
  (data (i32.const 16) "\"hello\"")
  (data (i32.const 32) "[{\"code\":\"console.log('hello from wasm')\",\"hosts\":[\"example.com\"]}]")

  (func (export "sbrs_abi_version") (result i32)
    (i32.const 1))

  ;; Pointer 16 in the high half, length 7 in the low half.
  (func (export "sbrs_name") (result i64)
    (i64.const 0x0000_0010_0000_0007))

  ;; Pointer 32, length 67.
  (func (export "sbrs_scripts") (result i64)
    (i64.const 0x0000_0020_0000_0043)))
