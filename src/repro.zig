const T = extern struct {
    a: u16,
    b: u32 align(2),
};

test "all" {
    var foo: *const T = undefined;
}
