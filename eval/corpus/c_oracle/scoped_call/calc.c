int helper(void) {
    return 1;
}

struct Config {
    int limit;
};

int run(struct Config c) {
    int base = helper();
    return base + c.limit;
}
