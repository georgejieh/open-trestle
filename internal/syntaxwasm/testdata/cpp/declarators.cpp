// Out-of-line definitions in a nested namespace and declarations with several declarators.
namespace outer::inner { void g(); }
void outer::inner::g() {}
void Widget::draw() {}
int size = sizeof(const int), count = 0;
int first = make(), second = build();
const int limit = 4, *cursor = nullptr;
