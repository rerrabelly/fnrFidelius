/**
 * @name Find GET Endpoint Methods with Annotations
 * @description Finds GET endpoints by checking method annotations
 * @kind problem
 * @problem.severity recommendation
 * @id java/find-get-with-annotations
 */

import java

from Method m, Annotation ann
where
  m.getDeclaringType().getName().matches("%FideliusController%") and
  ann = m.getAnAnnotation() and
  (
    ann.getType().getName().matches("%GetMapping%") or
    ann.getType().getName().matches("%RequestMapping%")
  )
select m,
  "GET Endpoint: " + m.getName() +
  " [@" + ann.getType().getName() + "]" +
  " in " + m.getDeclaringType().getName() +
  " at line " + m.getLocation().getStartLine().toString()
