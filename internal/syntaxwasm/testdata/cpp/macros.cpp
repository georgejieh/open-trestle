// Macro-heavy C++: test-framework style code and generated declarations.
#include <gtest/gtest.h>
#include "widget.hpp"

#define DECLARE_PROP(type, name) \
    type name##_;                \
    type name() const { return name##_; }

TEST(WidgetTest, DefaultsAreEmpty) {
    Widget w;
    int count = w.size();
    EXPECT_EQ(count, 0);
}

TEST_F(WidgetFixture, GrowsOnInsert) {
    widget.insert(1);
    EXPECT_EQ(widget.size(), 1);
}

BOOST_AUTO_TEST_CASE(parses) {
    int parsed = parse("1");
    BOOST_CHECK(parsed == 1);
}

class Widget {
public:
    DECLARE_PROP(int, width)
    DECLARE_PROP(int, height)
    Q_OBJECT
    void insert(int v);
    int size() const;
};

void Widget::insert(int v) { items.push_back(v); }
int Widget::size() const { return static_cast<int>(items.size()); }

EXPORT_API int exported_function(int x) { return x; }
