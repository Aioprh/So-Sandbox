package com.example.anative.core;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * 调用图构建与导出。
 *
 * <p>数据来自 {@link XRefScanner}：它已经把 .text 段里所有 BL/B 的目标解析成了
 * caller→callee 边。这里在其上做两件事：
 *
 * <ul>
 *   <li><b>ego 图</b>：以某个函数为中心，向 callers / callees 两侧各展开 N 层，
 *       这是逆向时最常用的视图——"谁调我、我调谁"</li>
 *   <li><b>导出</b>：DOT（Graphviz）与 Mermaid，前者能出高质量矢量图，
 *       后者可以直接贴进 Markdown / 飞书文档</li>
 * </ul>
 *
 * <p>节点用虚拟偏移标识。未在函数表里的目标用 {@code sub_XXXX} 命名，
 * 与函数列表的命名保持一致。
 */
public final class CallGraph {

    public static final class Node {
        public final long offset;
        public String name;
        /** 直接调用者数量（入度） */
        public int inDegree;
        /** 直接被调用数量（出度） */
        public int outDegree;
        /** 距中心节点的层数，0 表示中心 */
        public int depth;

        Node(long offset, String name) {
            this.offset = offset;
            this.name = name;
        }
    }

    public static final class Edge {
        public final long from;
        public final long to;
        /** 调用指令所在地址 */
        public final long instrAddr;

        Edge(long from, long to, long instrAddr) {
            this.from = from;
            this.to = to;
            this.instrAddr = instrAddr;
        }
    }

    public final Map<Long, Node> nodes = new LinkedHashMap<>();
    public final List<Edge> edges = new ArrayList<>();
    public long center = -1;
    public boolean truncated;

    private CallGraph() {
    }

    /**
     * 构建以 {@code centerOffset} 为中心的 ego 图。
     *
     * @param direction 1 = 只看被调用（callees），-1 = 只看调用者，0 = 双向
     * @param depth     展开层数，建议 2-3；层数越大节点爆炸越快
     * @param maxNodes  节点上限，超过即截断并置 {@link #truncated}
     */
    public static CallGraph ego(XRefScanner scanner, List<NativeFunction> functions,
                                long centerOffset, int direction, int depth, int maxNodes) {
        CallGraph g = new CallGraph();
        g.center = centerOffset;
        if (scanner == null) return g;

        Map<Long, String> nameByOffset = new LinkedHashMap<>();
        if (functions != null) {
            for (NativeFunction f : functions) {
                nameByOffset.put(f.getOffset(), f.getDemangledName());
            }
        }

        Deque<long[]> queue = new ArrayDeque<>();
        queue.add(new long[]{centerOffset, 0});
        Set<Long> visited = new LinkedHashSet<>();
        visited.add(centerOffset);

        Node root = new Node(centerOffset, nameOf(nameByOffset, centerOffset));
        root.depth = 0;
        g.nodes.put(centerOffset, root);

        while (!queue.isEmpty()) {
            long[] cur = queue.poll();
            long off = cur[0];
            int d = (int) cur[1];
            if (d >= depth) continue;

            if (direction >= 0) {
                for (XRefScanner.CallRef ref : scanner.getCalleesOf(off)) {
                    long target = ref.callerFuncOffset; // CallRef 在 callees 列表里存的是被调方
                    addEdge(g, off, target, ref.instrOffset, nameByOffset);
                    if (visited.add(target)) {
                        g.nodes.get(target).depth = d + 1;
                        queue.add(new long[]{target, d + 1});
                    }
                }
            }
            if (direction <= 0) {
                for (XRefScanner.CallRef ref : scanner.getCallersOf(off)) {
                    long caller = ref.callerFuncOffset;
                    addEdge(g, caller, off, ref.instrOffset, nameByOffset);
                    if (visited.add(caller)) {
                        g.nodes.get(caller).depth = d + 1;
                        queue.add(new long[]{caller, d + 1});
                    }
                }
            }
            if (maxNodes > 0 && g.nodes.size() > maxNodes) {
                g.truncated = true;
                break;
            }
        }

        g.recount();
        return g;
    }

    /** 全量调用图（不做 BFS 截断），节点数受 maxNodes 保护 */
    public static CallGraph full(XRefScanner scanner, List<NativeFunction> functions, int maxNodes) {
        CallGraph g = new CallGraph();
        if (scanner == null || functions == null) return g;

        Map<Long, String> nameByOffset = new LinkedHashMap<>();
        for (NativeFunction f : functions) nameByOffset.put(f.getOffset(), f.getDemangledName());

        for (NativeFunction f : functions) {
            if (maxNodes > 0 && g.nodes.size() >= maxNodes) {
                g.truncated = true;
                break;
            }
            long from = f.getOffset();
            for (XRefScanner.CallRef ref : scanner.getCalleesOf(from)) {
                addEdge(g, from, ref.callerFuncOffset, ref.instrOffset, nameByOffset);
                if (maxNodes > 0 && g.nodes.size() >= maxNodes) {
                    g.truncated = true;
                    break;
                }
            }
        }
        g.recount();
        return g;
    }

    private static void addEdge(CallGraph g, long from, long to, long instrAddr,
                                Map<Long, String> names) {
        if (from == to) return; // 自递归单独统计意义不大，且会让图出现自环
        g.nodes.computeIfAbsent(from, k -> new Node(k, nameOf(names, k)));
        g.nodes.computeIfAbsent(to, k -> new Node(k, nameOf(names, k)));
        for (Edge e : g.edges) {
            if (e.from == from && e.to == to) return; // 同一对只保留一条边，避免视觉噪声
        }
        g.edges.add(new Edge(from, to, instrAddr));
    }

    private static String nameOf(Map<Long, String> names, long off) {
        String n = names.get(off);
        if (n != null && !n.isEmpty()) return n;
        return String.format(Locale.US, "sub_%X", off);
    }

    private void recount() {
        for (Node n : nodes.values()) {
            n.inDegree = 0;
            n.outDegree = 0;
        }
        for (Edge e : edges) {
            Node a = nodes.get(e.from);
            Node b = nodes.get(e.to);
            if (a != null) a.outDegree++;
            if (b != null) b.inDegree++;
        }
    }

    /** 找出图中的环（简单 DFS，返回每个环的节点序列），用于识别递归/互相调用 */
    public List<List<Long>> findCycles(int maxCycles) {
        List<List<Long>> cycles = new ArrayList<>();
        Set<Long> visiting = new LinkedHashSet<>();
        Set<Long> done = new LinkedHashSet<>();
        Map<Long, List<Long>> adj = new LinkedHashMap<>();
        for (Edge e : edges) {
            adj.computeIfAbsent(e.from, k -> new ArrayList<>()).add(e.to);
        }
        for (Long n : nodes.keySet()) {
            if (!done.contains(n)) dfsCycle(n, adj, visiting, done, new ArrayList<>(), cycles, maxCycles);
            if (cycles.size() >= maxCycles) break;
        }
        return cycles;
    }

    private void dfsCycle(long node, Map<Long, List<Long>> adj, Set<Long> visiting,
                          Set<Long> done, List<Long> path, List<List<Long>> cycles, int maxCycles) {
        if (cycles.size() >= maxCycles) return;
        visiting.add(node);
        path.add(node);
        for (Long next : adj.getOrDefault(node, java.util.Collections.emptyList())) {
            if (visiting.contains(next)) {
                int idx = path.indexOf(next);
                if (idx >= 0) cycles.add(new ArrayList<>(path.subList(idx, path.size())));
                continue;
            }
            if (!done.contains(next)) {
                dfsCycle(next, adj, visiting, done, path, cycles, maxCycles);
            }
        }
        path.remove(path.size() - 1);
        visiting.remove(node);
        done.add(node);
    }

    /** 按出度排序的"热点"函数（被调用最多的） */
    public List<Node> hottest(int limit) {
        List<Node> list = new ArrayList<>(nodes.values());
        list.sort(Comparator.comparingInt((Node n) -> n.inDegree).reversed()
                .thenComparing(n -> n.name));
        return list.subList(0, Math.min(limit, list.size()));
    }

    public String toDot(boolean leftToRight) {
        StringBuilder sb = new StringBuilder();
        sb.append("digraph callgraph {\n");
        sb.append("  rankdir=").append(leftToRight ? "LR" : "TB").append(";\n");
        sb.append("  node [shape=box, style=\"rounded,filled\", fontname=\"Helvetica\", ")
                .append("fillcolor=\"#eef3ff\", color=\"#7a8fb8\"];\n");
        sb.append("  edge [color=\"#9aa7bd\", arrowsize=0.7];\n");

        for (Node n : nodes.values()) {
            String fill = n.offset == center ? "#ffe9b8" : "#eef3ff";
            sb.append(String.format(Locale.US,
                    "  \"0x%X\" [label=\"%s\\n0x%X\", fillcolor=\"%s\"];\n",
                    n.offset, dotEscape(n.name), n.offset, fill));
        }
        for (Edge e : edges) {
            sb.append(String.format(Locale.US, "  \"0x%X\" -> \"0x%X\";\n", e.from, e.to));
        }
        sb.append("}\n");
        return sb.toString();
    }

    public String toMermaid() {
        StringBuilder sb = new StringBuilder("graph LR\n");
        for (Node n : nodes.values()) {
            sb.append(String.format(Locale.US, "  n%x[\"%s\"]\n", n.offset, mmEscape(n.name)));
        }
        for (Edge e : edges) {
            sb.append(String.format(Locale.US, "  n%x --> n%x\n", e.from, e.to));
        }
        return sb.toString();
    }

    /** 纯文本邻接表，便于灌进 AI 上下文或写日志 */
    public String toText(int maxNodes) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format(Locale.US, "节点 %d，边 %d%s\n\n",
                nodes.size(), edges.size(), truncated ? "（已截断）" : ""));
        List<Node> sorted = new ArrayList<>(nodes.values());
        sorted.sort(Comparator.comparingInt((Node n) -> n.depth).thenComparing(n -> n.name));
        int n = 0;
        for (Node node : sorted) {
            if (n++ >= maxNodes) {
                sb.append("...\n");
                break;
            }
            sb.append(String.format(Locale.US, "%s  @0x%X  ← %d  → %d\n",
                    node.name, node.offset, node.inDegree, node.outDegree));
            for (Edge e : edges) {
                if (e.from != node.offset) continue;
                Node to = nodes.get(e.to);
                if (to != null) {
                    sb.append("    → ").append(to.name)
                            .append(String.format(Locale.US, " @0x%X", to.offset)).append('\n');
                }
            }
        }
        return sb.toString();
    }

    private static String dotEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ");
    }

    private static String mmEscape(String s) {
        if (s == null) return "";
        return s.replace("\"", "'").replace("[", "(").replace("]", ")").replace("\n", " ");
    }
}
