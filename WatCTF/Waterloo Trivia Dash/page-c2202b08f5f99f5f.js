(self.webpackChunk_N_E = self.webpackChunk_N_E || []).push([
  [974],
  {
    2757: (e, t, r) => {
      "use strict";
      Object.defineProperty(t, "__esModule", { value: !0 }),
        !(function (e, t) {
          for (var r in t)
            Object.defineProperty(e, r, { enumerable: !0, get: t[r] });
        })(t, {
          formatUrl: function () {
            return s;
          },
          formatWithValidation: function () {
            return a;
          },
          urlObjectKeys: function () {
            return l;
          },
        });
      let n = r(6966)._(r(8859)),
        o = /https?|ftp|gopher|file/;
      function s(e) {
        let { auth: t, hostname: r } = e,
          s = e.protocol || "",
          l = e.pathname || "",
          a = e.hash || "",
          i = e.query || "",
          u = !1;
        (t = t ? encodeURIComponent(t).replace(/%3A/i, ":") + "@" : ""),
          e.host
            ? (u = t + e.host)
            : r &&
              ((u = t + (~r.indexOf(":") ? "[" + r + "]" : r)),
              e.port && (u += ":" + e.port)),
          i &&
            "object" == typeof i &&
            (i = String(n.urlQueryToSearchParams(i)));
        let c = e.search || (i && "?" + i) || "";
        return (
          s && !s.endsWith(":") && (s += ":"),
          e.slashes || ((!s || o.test(s)) && !1 !== u)
            ? ((u = "//" + (u || "")), l && "/" !== l[0] && (l = "/" + l))
            : u || (u = ""),
          a && "#" !== a[0] && (a = "#" + a),
          c && "?" !== c[0] && (c = "?" + c),
          "" +
            s +
            u +
            (l = l.replace(/[?#]/g, encodeURIComponent)) +
            (c = c.replace("#", "%23")) +
            a
        );
      }
      let l = [
        "auth",
        "hash",
        "host",
        "hostname",
        "href",
        "path",
        "pathname",
        "port",
        "protocol",
        "query",
        "search",
        "slashes",
      ];
      function a(e) {
        return s(e);
      }
    },
    3792: (e, t, r) => {
      "use strict";
      r.r(t), r.d(t, { default: () => i });
      var n = r(5155),
        o = r(6874),
        s = r.n(o),
        l = r(2115);
      let a = [
        {
          prompt: "Which research institute is based in Waterloo?",
          options: [
            "CERN",
            "Perimeter Institute for Theoretical Physics",
            "Brookhaven National Laboratory",
            "Max Planck Institute",
          ],
          correctIndex: 1,
        },
        {
          prompt: "Which university is in Waterloo?",
          options: [
            "Harvard University",
            "University of Waterloo",
            "UCLA",
            "ETH Z\xfcrich",
          ],
          correctIndex: 1,
        },
        {
          prompt: "Which tech company was famously founded in Waterloo?",
          options: ["BlackBerry (RIM)", "Nokia", "Sony", "Xiaomi"],
          correctIndex: 0,
        },
      ];
      function i() {
        let [e, t] = (0, l.useState)(0),
          [r, o] = (0, l.useState)(0),
          [i, u] = (0, l.useState)(!1),
          [c, f] = (0, l.useState)(null),
          d = i ? 100 : Math.floor((e / a.length) * 100),
          p = (r) => {
            if (i) return;
            let n = r === a[e].correctIndex;
            f(n ? "Correct!" : "Wrong, try the next one."),
              n && o((e) => e + 1);
            let s = e + 1;
            s >= a.length ? u(!0) : t(s);
          },
          h = () => {
            t(0), o(0), u(!1), f(null);
          };
        return (0, n.jsxs)("div", {
          className:
            "items-center justify-items-center min-h-screen sm:p-20 font-[family-name:var(--font-geist-sans)]",
          children: [
            (0, n.jsx)("h1", {
              className: "text-4xl font-bold",
              children: "Waterloo Trivia Dash",
            }),
            (0, n.jsxs)("main", {
              className:
                "flex flex-col mt-8 gap-[24px] row-start-2 items-center sm:items-start w-200 max-w-xl",
              children: [
                (0, n.jsxs)("div", {
                  className: "w-full",
                  children: [
                    (0, n.jsx)("div", {
                      className: "h-2 w-full bg-gray-200 rounded",
                      children: (0, n.jsx)("div", {
                        className: "h-2 bg-blue-500 rounded",
                        style: { width: "".concat(d, "%") },
                      }),
                    }),
                    (0, n.jsxs)("div", {
                      className: "text-xs text-gray-600 mt-1",
                      children: [d, "% complete"],
                    }),
                  ],
                }),
                i
                  ? (0, n.jsxs)(n.Fragment, {
                      children: [
                        (0, n.jsx)("div", {
                          className: "text-2xl font-semibold",
                          children: "All done!",
                        }),
                        (0, n.jsxs)("div", {
                          className: "text-lg",
                          children: ["Your score: ", r, " / ", a.length],
                        }),
                        (0, n.jsx)("div", {
                          className: "text-sm text-gray-600",
                          children: "Claim your prize:",
                        }),
                        (0, n.jsx)("button", {
                          className: "font-bold py-2 px-4 rounded border",
                          children: (0, n.jsx)(s(), {
                            href: "/admin",
                            children: "Open Prize Page",
                          }),
                        }),
                        (0, n.jsx)("button", {
                          className:
                            "ml-2 text-sm text-blue-600 hover:underline",
                          onClick: h,
                          children: "Play again",
                        }),
                      ],
                    })
                  : (0, n.jsxs)(n.Fragment, {
                      children: [
                        (0, n.jsxs)("div", {
                          className: "text-lg",
                          children: ["Question ", e + 1, " of ", a.length],
                        }),
                        (0, n.jsx)("div", {
                          className: "text-2xl font-semibold",
                          children: a[e].prompt,
                        }),
                        (0, n.jsx)("div", {
                          className: "flex flex-col gap-2 mt-2 w-full",
                          children: a[e].options.map((e, t) =>
                            (0, n.jsx)(
                              "button",
                              {
                                className:
                                  "text-left font-bold py-2 px-4 rounded border hover:bg-gray-50",
                                onClick: () => p(t),
                                children: e,
                              },
                              t
                            )
                          ),
                        }),
                        c &&
                          (0, n.jsx)("div", {
                            className: "text-sm text-gray-600",
                            children: c,
                          }),
                        (0, n.jsxs)("div", {
                          className:
                            "flex items-center justify-between w-full mt-2",
                          children: [
                            (0, n.jsxs)("div", {
                              className: "text-sm",
                              children: ["Score: ", r],
                            }),
                            (0, n.jsx)("button", {
                              className:
                                "text-sm text-blue-600 hover:underline",
                              onClick: h,
                              children: "Reset",
                            }),
                          ],
                        }),
                      ],
                    }),
              ],
            }),
            (0, n.jsx)("footer", {
              className:
                "row-start-3 flex gap-[24px] flex-wrap items-center justify-center",
            }),
          ],
        });
      }
    },
    4356: (e, t, r) => {
      Promise.resolve().then(r.bind(r, 3792));
    },
    6654: (e, t, r) => {
      "use strict";
      Object.defineProperty(t, "__esModule", { value: !0 }),
        Object.defineProperty(t, "useMergedRef", {
          enumerable: !0,
          get: function () {
            return o;
          },
        });
      let n = r(2115);
      function o(e, t) {
        let r = (0, n.useRef)(null),
          o = (0, n.useRef)(null);
        return (0, n.useCallback)(
          (n) => {
            if (null === n) {
              let e = r.current;
              e && ((r.current = null), e());
              let t = o.current;
              t && ((o.current = null), t());
            } else e && (r.current = s(e, n)), t && (o.current = s(t, n));
          },
          [e, t]
        );
      }
      function s(e, t) {
        if ("function" != typeof e)
          return (
            (e.current = t),
            () => {
              e.current = null;
            }
          );
        {
          let r = e(t);
          return "function" == typeof r ? r : () => e(null);
        }
      }
      ("function" == typeof t.default ||
        ("object" == typeof t.default && null !== t.default)) &&
        void 0 === t.default.__esModule &&
        (Object.defineProperty(t.default, "__esModule", { value: !0 }),
        Object.assign(t.default, t),
        (e.exports = t.default));
    },
    6874: (e, t, r) => {
      "use strict";
      Object.defineProperty(t, "__esModule", { value: !0 }),
        Object.defineProperty(t, "default", {
          enumerable: !0,
          get: function () {
            return h;
          },
        });
      let n = r(8229),
        o = r(5155),
        s = n._(r(2115)),
        l = r(2757),
        a = r(5227),
        i = r(9818),
        u = r(6654),
        c = r(9991),
        f = r(5929);
      r(3230);
      let d = r(4930);
      function p(e) {
        return "string" == typeof e ? e : (0, l.formatUrl)(e);
      }
      let h = s.default.forwardRef(function (e, t) {
        let r, n;
        let {
          href: l,
          as: h,
          children: m,
          prefetch: y = null,
          passHref: x,
          replace: g,
          shallow: b,
          scroll: v,
          onClick: j,
          onMouseEnter: N,
          onTouchStart: P,
          legacyBehavior: E = !1,
          ..._
        } = e;
        (r = m),
          E &&
            ("string" == typeof r || "number" == typeof r) &&
            (r = (0, o.jsx)("a", { children: r }));
        let O = s.default.useContext(a.AppRouterContext),
          C = !1 !== y,
          w = null === y ? i.PrefetchKind.AUTO : i.PrefetchKind.FULL,
          { href: S, as: k } = s.default.useMemo(() => {
            let e = p(l);
            return { href: e, as: h ? p(h) : e };
          }, [l, h]);
        E && (n = s.default.Children.only(r));
        let T = E ? n && "object" == typeof n && n.ref : t,
          M = s.default.useCallback(
            (e) => (
              C && null !== O && (0, d.mountLinkInstance)(e, S, O, w),
              () => {
                (0, d.unmountLinkInstance)(e);
              }
            ),
            [C, S, O, w]
          ),
          I = {
            ref: (0, u.useMergedRef)(M, T),
            onClick(e) {
              E || "function" != typeof j || j(e),
                E &&
                  n.props &&
                  "function" == typeof n.props.onClick &&
                  n.props.onClick(e),
                O &&
                  !e.defaultPrevented &&
                  !(function (e, t, r, n, o, l, a) {
                    let { nodeName: i } = e.currentTarget;
                    !(
                      "A" === i.toUpperCase() &&
                      (function (e) {
                        let t = e.currentTarget.getAttribute("target");
                        return (
                          (t && "_self" !== t) ||
                          e.metaKey ||
                          e.ctrlKey ||
                          e.shiftKey ||
                          e.altKey ||
                          (e.nativeEvent && 2 === e.nativeEvent.which)
                        );
                      })(e)
                    ) &&
                      (e.preventDefault(),
                      s.default.startTransition(() => {
                        let e = null == a || a;
                        "beforePopState" in t
                          ? t[o ? "replace" : "push"](r, n, {
                              shallow: l,
                              scroll: e,
                            })
                          : t[o ? "replace" : "push"](n || r, { scroll: e });
                      }));
                  })(e, O, S, k, g, b, v);
            },
            onMouseEnter(e) {
              E || "function" != typeof N || N(e),
                E &&
                  n.props &&
                  "function" == typeof n.props.onMouseEnter &&
                  n.props.onMouseEnter(e),
                O && C && (0, d.onNavigationIntent)(e.currentTarget);
            },
            onTouchStart: function (e) {
              E || "function" != typeof P || P(e),
                E &&
                  n.props &&
                  "function" == typeof n.props.onTouchStart &&
                  n.props.onTouchStart(e),
                O && C && (0, d.onNavigationIntent)(e.currentTarget);
            },
          };
        return (
          (0, c.isAbsoluteUrl)(k)
            ? (I.href = k)
            : (E && !x && ("a" !== n.type || "href" in n.props)) ||
              (I.href = (0, f.addBasePath)(k)),
          E
            ? s.default.cloneElement(n, I)
            : (0, o.jsx)("a", { ..._, ...I, children: r })
        );
      });
      ("function" == typeof t.default ||
        ("object" == typeof t.default && null !== t.default)) &&
        void 0 === t.default.__esModule &&
        (Object.defineProperty(t.default, "__esModule", { value: !0 }),
        Object.assign(t.default, t),
        (e.exports = t.default));
    },
    8859: (e, t) => {
      "use strict";
      function r(e) {
        let t = {};
        for (let [r, n] of e.entries()) {
          let e = t[r];
          void 0 === e
            ? (t[r] = n)
            : Array.isArray(e)
            ? e.push(n)
            : (t[r] = [e, n]);
        }
        return t;
      }
      function n(e) {
        return "string" == typeof e
          ? e
          : ("number" != typeof e || isNaN(e)) && "boolean" != typeof e
          ? ""
          : String(e);
      }
      function o(e) {
        let t = new URLSearchParams();
        for (let [r, o] of Object.entries(e))
          if (Array.isArray(o)) for (let e of o) t.append(r, n(e));
          else t.set(r, n(o));
        return t;
      }
      function s(e) {
        for (
          var t = arguments.length, r = Array(t > 1 ? t - 1 : 0), n = 1;
          n < t;
          n++
        )
          r[n - 1] = arguments[n];
        for (let t of r) {
          for (let r of t.keys()) e.delete(r);
          for (let [r, n] of t.entries()) e.append(r, n);
        }
        return e;
      }
      Object.defineProperty(t, "__esModule", { value: !0 }),
        !(function (e, t) {
          for (var r in t)
            Object.defineProperty(e, r, { enumerable: !0, get: t[r] });
        })(t, {
          assign: function () {
            return s;
          },
          searchParamsToUrlQuery: function () {
            return r;
          },
          urlQueryToSearchParams: function () {
            return o;
          },
        });
    },
    9991: (e, t) => {
      "use strict";
      Object.defineProperty(t, "__esModule", { value: !0 }),
        !(function (e, t) {
          for (var r in t)
            Object.defineProperty(e, r, { enumerable: !0, get: t[r] });
        })(t, {
          DecodeError: function () {
            return h;
          },
          MiddlewareNotFoundError: function () {
            return g;
          },
          MissingStaticPage: function () {
            return x;
          },
          NormalizeError: function () {
            return m;
          },
          PageNotFoundError: function () {
            return y;
          },
          SP: function () {
            return d;
          },
          ST: function () {
            return p;
          },
          WEB_VITALS: function () {
            return r;
          },
          execOnce: function () {
            return n;
          },
          getDisplayName: function () {
            return i;
          },
          getLocationOrigin: function () {
            return l;
          },
          getURL: function () {
            return a;
          },
          isAbsoluteUrl: function () {
            return s;
          },
          isResSent: function () {
            return u;
          },
          loadGetInitialProps: function () {
            return f;
          },
          normalizeRepeatedSlashes: function () {
            return c;
          },
          stringifyError: function () {
            return b;
          },
        });
      let r = ["CLS", "FCP", "FID", "INP", "LCP", "TTFB"];
      function n(e) {
        let t,
          r = !1;
        return function () {
          for (var n = arguments.length, o = Array(n), s = 0; s < n; s++)
            o[s] = arguments[s];
          return r || ((r = !0), (t = e(...o))), t;
        };
      }
      let o = /^[a-zA-Z][a-zA-Z\d+\-.]*?:/,
        s = (e) => o.test(e);
      function l() {
        let { protocol: e, hostname: t, port: r } = window.location;
        return e + "//" + t + (r ? ":" + r : "");
      }
      function a() {
        let { href: e } = window.location,
          t = l();
        return e.substring(t.length);
      }
      function i(e) {
        return "string" == typeof e ? e : e.displayName || e.name || "Unknown";
      }
      function u(e) {
        return e.finished || e.headersSent;
      }
      function c(e) {
        let t = e.split("?");
        return (
          t[0].replace(/\\/g, "/").replace(/\/\/+/g, "/") +
          (t[1] ? "?" + t.slice(1).join("?") : "")
        );
      }
      async function f(e, t) {
        let r = t.res || (t.ctx && t.ctx.res);
        if (!e.getInitialProps)
          return t.ctx && t.Component
            ? { pageProps: await f(t.Component, t.ctx) }
            : {};
        let n = await e.getInitialProps(t);
        if (r && u(r)) return n;
        if (!n)
          throw Object.defineProperty(
            Error(
              '"' +
                i(e) +
                '.getInitialProps()" should resolve to an object. But found "' +
                n +
                '" instead.'
            ),
            "__NEXT_ERROR_CODE",
            { value: "E394", enumerable: !1, configurable: !0 }
          );
        return n;
      }
      let d = "undefined" != typeof performance,
        p =
          d &&
          ["mark", "measure", "getEntriesByName"].every(
            (e) => "function" == typeof performance[e]
          );
      class h extends Error {}
      class m extends Error {}
      class y extends Error {
        constructor(e) {
          super(),
            (this.code = "ENOENT"),
            (this.name = "PageNotFoundError"),
            (this.message = "Cannot find module for page: " + e);
        }
      }
      class x extends Error {
        constructor(e, t) {
          super(),
            (this.message =
              "Failed to load static file for page: " + e + " " + t);
        }
      }
      class g extends Error {
        constructor() {
          super(),
            (this.code = "ENOENT"),
            (this.message = "Cannot find the middleware module");
        }
      }
      function b(e) {
        return JSON.stringify({ message: e.message, stack: e.stack });
      }
    },
  },
  (e) => {
    var t = (t) => e((e.s = t));
    e.O(0, [441, 684, 358], () => t(4356)), (_N_E = e.O());
  },
]);
