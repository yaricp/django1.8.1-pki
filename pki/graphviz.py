"""Graphviz support for django-pki"""

from .models import Certificate, CertificateAuthority
from .settings import PKI_ENABLE_GRAPHVIZ, PKI_GRAPHVIZ_DIRECTION

if PKI_ENABLE_GRAPHVIZ is True:
    try:
        import pygraphviz as pgv
    except ImportError as e:
        raise Exception("Failed to import pygraphviz. Disable PKI_ENABLE_GRAPHVIZ or install pygraphviz: %s" % e)


def object_chain(object, target):
    """Render object chain PNG.
    Render a graphviz image for the given object and save the resulting PNG
    in target.
    """

    G = pgv.AGraph(directed=True, layout="dot", pad="0.2", rankdir="TB")

    if isinstance(object, Certificate):
        o_shape = "note"
    elif isinstance(object, CertificateAuthority):
        o_shape = "folder"
    else:
        raise Exception("Invalid object instance given!")

    # Set fill color bases in state
    if object.active:
        obj_fill = "green3"
    else:
        obj_fill = "red"

    edges = []

    # Add given object to graph
    G.add_node(object.common_name, shape=o_shape, style="filled, bold", fillcolor=obj_fill, fontcolor="white")

    # Get parents if any
    if object.parent:
        # Set p to objects parent
        p = object.parent

        # Add parent node to graph
        if p.active:
            p_color = "green3"
        else:
            p_color = "red"

        G.add_node(p.common_name, shape="folder", color=p_color, style="bold")

        # Set initial edge between requested onject and it's parent
        edges.append([p.common_name, object.common_name])

        while p:
            if p.active:
                col = "green3"
            else:
                col = "red"

            G.add_node(p.common_name, shape="folder", color=col, style="bold")

            if p.parent:
                edges.append([p.parent.common_name, p.common_name])

            p = p.parent

    # Draw the edges
    for e in edges:
        G.add_edge(e[0], e[1])

    G.layout()
    G.draw(target, format="png")

    return True


def object_tree(object, target):
    """Render object tree PNG.
    Render a graphviz image for the entire object tree object and save the resulting PNG
    in target.
    """

    def traverse_to_bottom(r_id, graph=None):
        """Traverse the PKI tree down from a given id"""

        c = CertificateAuthority.objects.get(id=r_id)

        if not c.is_edge_ca():
            x = CertificateAuthority.objects.filter(parent__id=c.pk)
        else:
            x = [c]

        for ca in x:
            if graph:
                if ca.active is True:
                    col = "green3"
                else:
                    col = "red"

                graph.add_node(ca.common_name, shape="folder", color=col, style="bold")

                # Prevent link to self when this is a toplevel edge rootca
                if ca != c:
                    graph.add_edge(c.common_name, ca.common_name, color="black", weight="4.5")

            if not ca.is_edge_ca():
                traverse_to_bottom(ca.pk, graph)
            else:
                certs = Certificate.objects.filter(parent__id=ca.pk)

                if certs:
                    subgraph_list = [ca.common_name]

                    for cert in certs:
                        subgraph_list.append(cert.common_name)

                        if graph:
                            if cert.active:
                                col = "green3"
                            else:
                                col = "red"

                            graph.add_node(str(cert.common_name), shape="note", color=col, style="bold")
                            graph.add_edge(ca.common_name, cert.common_name, color="black", weight="4.5")

                    # sg = graph.subgraph(
                    #    nbunch=subgraph_list, name="cluster_%d" % ca.pk, style="bold", color="black", label=""
                    # )

    G = pgv.AGraph(
        directed=True, layout="dot", pad="0.2", ranksep="1.00", nodesep="0.10", rankdir=PKI_GRAPHVIZ_DIRECTION
    )

    if object.active:
        obj_fill = "green3"
    else:
        obj_fill = "red"

    G.add_node(object.common_name, shape="folder", style="filled,bold", fillcolor=obj_fill, fontcolor="white")

    if not isinstance(object, CertificateAuthority):
        raise Exception("Object has to be of type CertificateAuthority, not %s" % object.__class__.__name__)

    # Find top parents
    if object.parent:
        p = object.parent

        while p:
            if not p.parent:
                if p.active:
                    col = "green3"
                else:
                    col = "red"

                G.add_node(p.common_name, shape="folder", color=col, style="bold")
                traverse_to_bottom(p.id, G)
            p = p.parent
    else:
        traverse_to_bottom(object.id, G)

    G.layout()
    G.draw(target, format="png")

    return True
