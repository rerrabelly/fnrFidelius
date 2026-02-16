/**
 * @name Find HTTP GET Endpoints (Simple)
 * @description Finds all HTTP GET endpoint methods by looking for annotations
 * @kind problem
 * @problem.severity recommendation
 * @id java/find-get-endpoints-simple
 */

import java

from Method m, Annotation ann, string annName
where
  ann = m.getAnAnnotation() and
  annName = ann.getType().getName() and
  (
    annName = "GetMapping" or
    annName = "RequestMapping"
  )
select m,
  "Endpoint: " + m.getDeclaringType().getName() + "." + m.getName() +
  " [@" + annName + "]" +
  " at " + m.getLocation().getFile().getBaseName() + ":" + m.getLocation().getStartLine()
