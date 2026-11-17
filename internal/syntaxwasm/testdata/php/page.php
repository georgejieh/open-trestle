<!doctype html>
<html>
<body>
<?php $title = strtoupper('home'); ?>
<h1><?= htmlspecialchars($title) ?></h1>
<?php foreach ($items as $item): ?>
  <p><?= render($item) ?></p>
<?php endforeach; ?>
<?php
function footer(): string { return '</body>'; }
?>
</body>
</html>
