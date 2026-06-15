int helper() {
    return 1;
}

struct Config {
    int limit;
};

int run(Config c) {
    int base = helper();
    return base + c.limit;
}
