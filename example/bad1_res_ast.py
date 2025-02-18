Module(
  body=[
    ImportFrom(
      module='os',
      names=[alias(
        name='system',
        asname=None)],
      level=0),
    Expr(value=Call(
      func=Name(
        id='system',
        ctx=Load()),
      args=[Constant(
        value="echo 'hello world'",
        kind=None)],
      keywords=[]))],
  type_ignores=[])