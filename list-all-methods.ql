/**
 * @name List All Methods
 * @description Lists all methods to see what's in the database
 * @kind problem
 * @problem.severity recommendation
 * @id java/list-all-methods
 */

import java

from Method m
where m.getDeclaringType().getName().matches("%Controller%")
select m,
  "Method: " + m.getDeclaringType().getName() + "." + m.getName() +
  " at " + m.getLocation().getFile().getBaseName() + ":" + m.getLocation().getStartLine()
