/**
 * @name Full call graph for GET /accounts endpoint (all calls)
 * @description Traces all method calls made within project methods reachable
 *              from FideliusController.getAccounts(), including library calls.
 * @kind problem
 * @problem.severity recommendation
 * @id custom/accounts-call-graph-full
 * @tags spring
 *       call-graph
 */

import java

Method getEntryPoint() {
  result.getName() = "getAccounts" and
  result.getDeclaringType().getName() = "FideliusController"
}

/**
 * Holds if `caller` is a project method that calls `callee` (any method).
 */
predicate callFromProject(Method caller, MethodCall mc, Method callee) {
  mc.getEnclosingCallable() = caller and
  mc.getMethod() = callee and
  caller.getDeclaringType().getPackage().getName().matches("org.finra.fidelius%")
}

/**
 * Holds if `m` is a project method reachable from the entry point.
 */
predicate reachableProjectMethod(Method m, int depth) {
  m = getEntryPoint() and depth = 0
  or
  exists(Method caller, MethodCall mc, int d |
    reachableProjectMethod(caller, d) and
    d < 10 and
    callFromProject(caller, mc, m) and
    m.getDeclaringType().getPackage().getName().matches("org.finra.fidelius%") and
    depth = d + 1
  )
}

from Method caller, MethodCall mc, Method callee, int depth
where
  reachableProjectMethod(caller, depth) and
  callFromProject(caller, mc, callee)
select mc,
  "depth=" + depth.toString() +
  " | " + caller.getDeclaringType().getName() + "." + caller.getName() + "()" +
  " -> " + callee.getDeclaringType().getName() + "." + callee.getName() + "()" +
  " | at " + mc.getLocation().getFile().getBaseName() + ":" + mc.getLocation().getStartLine().toString()
