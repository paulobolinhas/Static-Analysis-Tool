from classes.label import Label
from classes.multi_label import MultiLabel


def test_combineLabels():
    label1 = Label()
    label1.add_tuple(("c", []))
    label1.add_tuple(("c", ["a"]))
    print("label 1 ", label1)

    label2 = Label()
    label2.add_tuple(("c", []))
    print("label 2 ", label2)

    label3 = label1.combine_labels(label2)
    print("label 3 ", label3)


    

test_combineLabels()