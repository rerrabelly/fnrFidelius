/**
 * @name Find GET Endpoints via Source Analysis
 * @description Finds methods in controller files that likely handle GET requests
 * @kind problem
 * @problem.severity recommendation
 * @id java/find-get-endpoints-source
 */

import java

from Method m, File f
where
  f = m.getLocation().getFile() and
  f.getBaseName().matches("%Controller.java") and
  m.getName().matches("get%") or m.getName().matches("%Endpoint")
select m,
  "Potential GET endpoint: " + m.getName() +
  " in " + m.getDeclaringType().getName() +
  " at " + f.getBaseName() + ":" + m.getLocation().getStartLine().toString()
