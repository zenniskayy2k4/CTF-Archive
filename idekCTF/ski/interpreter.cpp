/// `clang++ -std=c++20 -O3 -pipe -static -march=native -flto interpreter.cpp -o interpreter`
/// `g++ -std=c++20 -O3 -pipe -static -march=native -flto interpreter.cpp -o interpreter`
/// msvc is supported, but you're on your own :)
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

struct Term;
using TermPtr = Term*;
using CTermPtr = const Term*;

enum struct Tag : uint8_t {
    S,
    K,
    I,
    Var,
    App
};

struct alignas(8) Term {
    union {
        struct {
            TermPtr f, x;
        };
        uint32_t name;
    };
};

namespace detail {
    inline constexpr uintptr_t TAG_MASK = 0b111; // (<= 8 tags)
    inline constexpr uintptr_t PTR_MASK = ~TAG_MASK;

    inline TermPtr tag_ptr(Tag t, TermPtr p) noexcept {
        return reinterpret_cast<TermPtr>((reinterpret_cast<uintptr_t>(p) & PTR_MASK) | static_cast<uintptr_t>(t));
    }
    inline Tag get_tag(CTermPtr p) noexcept {
        return static_cast<Tag>(reinterpret_cast<uintptr_t>(p) & TAG_MASK);
    }
    inline TermPtr untag_ptr(TermPtr p) noexcept {
        return reinterpret_cast<TermPtr>(reinterpret_cast<uintptr_t>(p) & PTR_MASK);
    }
} // namespace detail

class AllocationArena {
    static constexpr std::size_t CHUNK = 1 << 20; // 1 MiB

    struct Chunk {
        Chunk* next;
        char data[CHUNK - sizeof(Chunk*)];
    };

    Chunk* head_ = nullptr;
    char* cur_ = nullptr;
    char* end_ = nullptr;

    void new_chunk() {
        auto* c = static_cast<Chunk*>(std::malloc(sizeof(Chunk)));
        if (!c) {
            throw std::bad_alloc{};
        }
        c->next = head_;
        head_ = c;
        cur_ = c->data;
        end_ = c->data + sizeof(c->data);
    }

public:
    ~AllocationArena() {
        while (head_) {
            Chunk* nxt = head_->next;
            std::free(head_);
            head_ = nxt;
        }
    }

    template <class... A>
    [[nodiscard]] TermPtr make(const Tag tag, A... a) {
        constexpr std::size_t need = sizeof(Term);
        if (cur_ == nullptr || cur_ + need > end_) {
            new_chunk();
        }

        auto* raw = reinterpret_cast<TermPtr>(cur_);
        cur_ += need;

        if constexpr (sizeof...(A) == 2) {
            raw->f = std::get<0>(std::tuple<A...>(a...));
            raw->x = std::get<1>(std::tuple<A...>(a...));
        } else if constexpr (sizeof...(A) == 1) {
            raw->name = std::get<0>(std::tuple<A...>(a...));
        }
        return detail::tag_ptr(tag, raw);
    }
} arena;

std::unordered_map<std::string_view, uint32_t> id_of;
std::vector<std::string_view> name_of;

[[nodiscard]] uint32_t intern(const std::string_view s) {
    if (const auto it = id_of.find(s); it != id_of.end()) {
        return it->second;
    }

    const auto id = static_cast<uint32_t>(name_of.size());
    /// CHECK: we are sure that the string will still be in memory
    auto [it, _] = id_of.emplace(s, id_of.size());
    name_of.emplace_back(it->first);
    return id;
}

[[nodiscard]] TermPtr S() {
    static TermPtr p = arena.make(Tag::S);
    return p;
}

[[nodiscard]] TermPtr K() {
    static TermPtr p = arena.make(Tag::K);
    return p;
}

[[nodiscard]] TermPtr I() {
    static TermPtr p = arena.make(Tag::I);
    return p;
}

[[nodiscard]] TermPtr Var(const uint32_t id) {
    return arena.make(Tag::Var, id);
}

[[nodiscard]] TermPtr App(TermPtr f, TermPtr x) {
    return arena.make(Tag::App, f, x);
}

template <class Node>
auto& get_f(Node* p) {
    return detail::untag_ptr(p)->f;
}
template <class Node>
auto& get_x(Node* p) {
    return detail::untag_ptr(p)->x;
}
template <class Node>
auto& get_name(Node* p) {
    return detail::untag_ptr(p)->name;
}

struct Parser {
    const char *s, *p;
    explicit Parser(const std::string_view src): s(src.data()), p(s) { }
    explicit Parser(const char* src): s(src), p(s) { }

    void trim_whitespaces() {
        while (isspace(*p)) {
            ++p;
        }
    }

    [[nodiscard]] TermPtr parse_term() {
        trim_whitespaces();
        if (*p == '(') {
            ++p;
            TermPtr t = parse_expr();
            trim_whitespaces();
            if (*p != ')')
                err();
            ++p;
            return t;
        }

        if (isalpha(*p) || *p == '_') {
            const char* b = p++;
            while (isalnum(*p) || *p == '_') {
                ++p;
            }

            std::string_view name(b, static_cast<std::size_t>(p - b));
            if (name == "S") {
                return S();
            }
            if (name == "K") {
                return K();
            }
            if (name == "I") {
                return I();
            }
            return Var(intern(name));
        }

        err();
    }

    TermPtr parse_expr() {
        TermPtr r = parse_term();
        while (true) {
            trim_whitespaces();
            if (*p == '(' || isalpha(*p) || *p == '_') {
                r = App(r, parse_term());
            } else {
                break;
            }
        }
        return r;
    }

    [[noreturn]] static void err() {
        throw std::runtime_error("parse error");
    }
};

std::string show(TermPtr t) {
    switch (detail::get_tag(t)) {
    case Tag::S:
        return "S";
    case Tag::K:
        return "K";
    case Tag::I:
        return "I";
    case Tag::Var:
        return std::string(name_of[get_name(t)]);
    case Tag::App:
        return "(" + show(get_f(t)) + " " + show(get_x(t)) + ")";
    }
    return "?";
}

struct PtrHash {
    [[nodiscard]] size_t operator()(TermPtr p) const noexcept {
        return reinterpret_cast<uintptr_t>(p);
    }
};

struct PtrEq {
    [[nodiscard]] bool operator()(const CTermPtr a, const CTermPtr b) const noexcept {
        return a == b;
    }
};

[[nodiscard]] TermPtr substitute(TermPtr in_term, const std::unordered_map<uint32_t, TermPtr>& env,
                                 std::unordered_map<TermPtr, TermPtr, PtrHash, PtrEq>& memo) {
    if (const auto it = memo.find(in_term); it != memo.end()) {
        return it->second;
    }

    TermPtr term = in_term;
    switch (detail::get_tag(in_term)) {
    case Tag::Var: {
        if (const auto ie = env.find(get_name(in_term)); ie != env.end()) {
            term = substitute(ie->second, env, memo);
        }
        break;
    }
    case Tag::App: {
        TermPtr f = substitute(get_f(in_term), env, memo);
        TermPtr x = substitute(get_x(in_term), env, memo);
        term = (f == get_f(in_term) && x == get_x(in_term)) ? in_term : App(f, x);
        break;
    }
    default: {
        break;
    }
    }
    memo.emplace(in_term, term);
    return term;
}

[[nodiscard]] TermPtr rebuild(TermPtr head, const std::span<TermPtr> args) {
    for (TermPtr a : args) {
        head = App(head, a);
    }
    return head;
}

[[nodiscard]] TermPtr step(TermPtr term) {
    std::vector<TermPtr> args = {};
    TermPtr h = term;

    while (detail::get_tag(h) == Tag::App) {
        args.push_back(get_x(h));
        h = get_f(h);
    }

    std::ranges::reverse(args);
    size_t argc = args.size();
    auto get_arg = [&](std::size_t i) -> TermPtr& {
        return args[i];
    };

    if (h == I() && argc >= 1) {
        if (argc == 1) {
            return get_arg(0);
        }

        return rebuild(get_arg(0), std::span(&get_arg(1), argc - 1));
    }

    if (h == K() && argc >= 2) {
        if (argc == 2) {
            return get_arg(0);
        }

        return rebuild(get_arg(0), std::span(&get_arg(2), argc - 2));
    }

    if (h == S() && argc >= 3) {
        TermPtr f = get_arg(0);
        TermPtr g = get_arg(1);
        TermPtr x = get_arg(2);

        std::vector<TermPtr> rest;
        rest.reserve(argc - 3);
        for (size_t i = 3; i < argc; ++i) {
            rest.push_back(get_arg(i));
        }

        TermPtr head = App(App(f, x), App(g, x));
        return rebuild(head, rest);
    }

    if (detail::get_tag(h) == Tag::App) {
        if (TermPtr h2 = step(h)) {
            return rebuild(h2, {&get_arg(0), argc});
        }
    }

    for (size_t i = 0; i < argc; ++i) {
        if (auto arg = get_arg(i); detail::get_tag(arg) == Tag::App) {
            if (TermPtr a2 = step(arg)) {
                args[i] = a2;
                return rebuild(h, {&get_arg(0), argc});
            }
        }
    }
    return nullptr;
}

std::pair<TermPtr, int> normal_form(TermPtr t) {
    static std::unordered_map<TermPtr, std::pair<TermPtr, int>, PtrHash, PtrEq> cache;
    if (const auto it = cache.find(t); it != cache.end()) {
        return it->second;
    }

    int n = 0;
    TermPtr cur = t;
    while (TermPtr nx = step(cur)) {
        cur = nx;
        ++n;
    }
    return cache.emplace(t, std::make_pair(cur, n)).first->second;
}

std::unordered_map<uint32_t, TermPtr> prelude(const std::string& flag, size_t max_bits = 128 * 8) {
    std::vector<int> bits;
    bits.reserve(max_bits);
    for (const auto c : flag) {
        for (int i = 7; i >= 0 && bits.size() < max_bits; --i) {
            bits.push_back((c >> i) & 1);
        }
    }

    while (bits.size() < max_bits) {
        bits.push_back(0);
    }

    std::unordered_map<uint32_t, TermPtr> env;
    for (size_t i = 0; i < max_bits; ++i) {
        env[intern("_F" + std::to_string(i))] = bits[i] ? K() : App(K(), I());
    }
    return env;
}

int main() try {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    std::ifstream fin("program.txt");
    if (!fin) {
        std::cerr << "Could not open program.txt\n";
        return 1;
    }

    std::string src(std::istreambuf_iterator(fin), {});

    std::string flag;
    std::cout << "₍^. .^₎⟆" << std::endl;
    std::cin >> flag;

    std::cout << "parsing" << std::endl;
    std::vector<std::pair<bool, TermPtr>> prog;
    const char* s = src.c_str();
    const char* e = s + src.size();

    while (s < e) {
        while (s < e && isspace(*s)) {
            ++s;
        }

        if (s == e) {
            break;
        }

        const char* id_b = s;
        while (s < e && !isspace(*s) && *s != '=') {
            ++s;
        }

        while (s < e && isspace(*s)) {
            ++s;
        }

        if (s < e && *s == '=') {
            ++s;

            auto name = std::string_view{id_b, static_cast<std::size_t>(s - id_b)};
            TermPtr rhs = Parser(s).parse_expr();
            prog.emplace_back(true, App(Var(intern(name)), rhs));
            s = e;
        } else {
            prog.emplace_back(false, Parser(id_b).parse_expr());
            break;
        }
    }

    auto env = prelude(flag);
    TermPtr last = nullptr;
    for (auto& [is_def, node] : prog) {
        std::unordered_map<TermPtr, TermPtr, PtrHash, PtrEq> memo;
        if (is_def) {
            env[node->f->name] = substitute(node->x, env, memo);
        } else {
            last = substitute(node, env, memo);
        }
    }

    std::cout << "reducing to normal form" << std::endl;
    auto [nf, steps] = normal_form(last);
    std::cout << "reduced in " << steps << " steps!\n";
    std::cout << "- nf: " << show(nf) << "\n";

    if (nf == K()) {
        std::cout << "- flag: correct\n";
    } else if (detail::get_tag(nf) == Tag::App && get_f(nf) == K() && get_x(nf) == I()) {
        std::cout << "- flag: incorrect\n";
    } else {
        std::cout << "- flag: unknown status\n";
    }

    return 0;
} catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << '\n';
    return 1;
}
