var w = $(window).width() - 10,
    h = 600,
    x = d3.scale.linear().range([0, w]),
    y = d3.scale.linear().range([0, h]);

var vis = d3.select("#body").append("xhtml:div")
    .attr("class", "chart")
    .style("width", w + "px")
    .style("height", h + "px")
  .append("svg:svg")
    .attr('xmlns','http://www.w3.org/2000/svg')
    .attr("width", w)
    .attr("height", h);

var partition = d3.layout.partition()
    .value(function(d) { return d.size; });

flow_info = {}

function table_init(headings, id){
    var body = document.getElementById("flow"+id);
    var tbl = document.createElement("table");
    var tblbody = document.createElement("tbody");
    var tblhead = document.createElement("thead");

    var row = document.createElement("tr");
    for(idx in headings){
        var cell = document.createElement("td");
        var cell_text = document.createTextNode(headings[idx]['name']);
        if ('tooltip' in headings[idx]){
            cell.setAttribute("title", headings[idx]['tooltip']);
        }
        cell.appendChild(cell_text);
        row.appendChild(cell);
    }

    tblhead.appendChild(row);
    tblbody.setAttribute("id", "table_body");

    tbl.appendChild(tblbody);
    tbl.appendChild(tblhead);
    body.appendChild(tbl);

    tbl.setAttribute("id", "table_id");
    tbl.setAttribute("class", "display cell-border");
    tbl.setAttribute("width", "100%");
    tbl.setAttribute("cellspacing", "0");
}


function render_tree(root){
    if(!root.name) return;
    var g = vis.selectAll("g")
      .data(partition.nodes(root))
      .enter().append("svg:g")
      .attr("transform", function(d) { return "translate(" + x(d.y) + "," + y(d.x) + ")"; })
      .on("click", click);

    var kx = w / root.dx,
      ky = h / 1;

    g.append("svg:rect")
      .attr("width", function(d) {
        return root.dy * kx;
        })
      .attr("height", function(d) { 
        return d.dx * ky; 
        })
      .attr("class", function(d) {
            return d.children ? (d.istable ?  "table" : "parent") : "child";
        })
      .attr("id", function(d){
        if(d.id) return d.id;
      })
      .attr("fill", function(d){return "steelblue"; });

    g.append("svg:foreignObject")
      .attr("transform", transform)
      .attr("dy", ".35em")
      .attr("id", function(d){return d.isflow ? "flow"+d.table_id: "id"; })
      .attr("class", function(d){return d.isflow ? "flows" : "";})
      .attr("height", "100%")
      .attr("width", "100%")
      .style("opacity", function(d) { return d.dx * ky > 12 ? 1 : 0; })
        .append("xhtml:div")        
        .text(function(d) { return d.name; })

    d3.select(window)
      .on("click", function() { click(root); })

    function click(d) {
        if(d.isflow){
            d3.event.stopPropagation();
            return;
        }

        if (!d.children) return;

        kx = (d.y ? w - 40 : w) / (1 - d.y);
        ky = h / d.dx;
        x.domain([d.y, 1]).range([d.y ? 40 : 0, w]);
        y.domain([d.x, d.x + d.dx]);

        var t = g.transition()
            .duration(d3.event.altKey ? 7500 : 750)
            .attr("transform", function(d) { return "translate(" + x(d.y) + "," + y(d.x) + ")"; });

        t.select("rect")
            .attr("width", d.dy * kx)
            .attr("height", function(d) { return d.dx * ky; });

        t.select("text")
            .attr("transform", transform)
            .style("opacity", function(d) { return d.dx * ky > 12 ? 1 : 0; });

        d3.event.stopPropagation();

        if(d.istable){
            $("foreignObject.flows").text("");   
            table_init([
                {'name': 'Duration_sec', 'tooltip': 'indicates how long ago a flow was inserted or refreshed'},
                {'name': 'Eth_src'},
                {'name': 'Eth_dst'},
                {'name': 'IP_src'},
                {'name': 'IP_dst'},
                {'name': 'IN_port'},
                {'name': 'Priority'}
            ], d.id);
            var tbl = document.getElementById('table_body');
            table_flows = flow_info[d.id];
            for (d_idx in table_flows){
                var row = document.createElement("tr");
                for (info_idx in table_flows[d_idx]){
                    var cell = document.createElement("td");
                    var cell_text = document.createTextNode(table_flows[d_idx][info_idx]);
                    cell.appendChild(cell_text);
                    row.appendChild(cell);
                }
                tbl.appendChild(row);
            }
            var table = $('#table_id').DataTable({
                    'iDisplayLength': 10
            });
        }

        if(d.depth == 0 || d.depth == 1){
            $("foreignObject.flows").text("Flows in this table");   
        }
    }

    function transform(d) {
        return "translate(8," + d.dx * ky / 2 + ")";
    }
}

tree = {'name': 'Faucet managed Switches', 'children':[], 'isRoot': true}
table_key_value = {"0": "VLAN", "1": "ACL"}
flow_switch_map = {}

function map_flows_and_switches(flows, switch_id){
    for(i in flows){
        flow_switch_map[flows[i]] = switch_id;
    }
}

function fetch_data(handle_data){
    $.ajax({
        type: "GET",
        url: window.location.protocol+"//"+window.location.host+"/switches_bak/_design/switches/_view/switch",
        dataType: 'json',
        success: function (resp_data) {
            handle_data(resp_data);
        },
        crossDomain: true
    });
}

fetch_data(function handle_data(data){
    result = data.rows
    for(i in result){
        switch_data = result[i];
        switch_id = switch_data.id;
        switch_flows = switch_data.value.data.flows;
        map_flows_and_switches(switch_flows, switch_id);
        console.log('[\"' + switch_flows.join('\",\"') + '\"]');
        $.ajax({
            type: "GET",
            url: window.location.protocol+"//"+window.location.host+"/flows_bak/_design/flows/_view/flow",
            data: {"keys": '[\"' + switch_flows.join('\",\"') + '\"]'},
            dataType: 'json',
            success: function (resp_data) {
                handle_flows(resp_data);
            },
            crossDomain: true
        });
    }
});

function parse_match(match){
    ret_data = {
        "esrc":"",
        "edst":"",
        "ipsrc":"",
        "ipdst":"",
        "in_port":""
    };
    oxm_fields = match.oxm_fields;
    if(oxm_fields.length > 0){
        for(idx in oxm_fields){
            mtlv = oxm_fields[idx].OXMTlv;
            if(mtlv.field == 'eth_dst'){
                ret_data['edst'] = mtlv.value;
            }
            else if(mtlv.field == 'eth_src'){
                ret_data['esrc'] = mtlv.value;
            }
            else if(mtlv.field == 'ipv4_src'){
                ret_data['ipsrc'] = mtlv.value;
            }
            else if(mtlv.field == 'ipv4_dst'){
                ret_data['ipdst'] = mtlv.value;
            }
            else if(mtlv.field == 'in_port'){
                ret_data['in_port'] = mtlv.value;
            }
        }
    }
    return ret_data;
}


function get_flow_info(flow){
    match = parse_match(flow.match.OFPMatch);
    return [
        flow.duration_sec,
        match.esrc,
        match.edst,
        match.ipsrc,
        match.ipdst,
        match.in_port,
        flow.priority
    ];
}


function handle_flows(flow_data){
    flows = flow_data.rows;
    table_sub_tree = []
    map_table_id_idx = {}
    switch_id = undefined;
    for(flow_idx in flows){
        if(!switch_id) switch_id = flow_switch_map[flows[flow_idx].id];

        flow_stats = flows[flow_idx].value.data.OFPFlowStats;
        table_id = flow_stats.table_id;
        if(!(switch_id+table_id in flow_info)){
            flow_info[switch_id+table_id] = [];
            flow_info[switch_id+table_id].push(get_flow_info(flow_stats));
        }
        else{
            flow_info[switch_id+table_id].push(get_flow_info(flow_stats));   
        }
        if(!(table_id in map_table_id_idx)){
            map_table_id_idx[table_id] = table_sub_tree.length;
            table_sub_tree.push({
                "name": "Table ID "+table_id,
                "istable": true,
                "id": switch_id+table_id,
                "children":[
                    {
                        "name": "Flows in this table",
                        "isflow": true,
                        "table_id": switch_id+table_id,
                        "size": 1
                    }
                ]
            });
        }
    }
    console.log(flows);
    tree.children.push({
        "name": "Switch ID "+switch_id,
        "id": switch_id,
        "children":table_sub_tree
    });
    console.log(map_table_id_idx);
    console.log(table_sub_tree);
    console.log(tree);
    console.log(flow_info);
}


$(document).ajaxStop(function(){
    render_tree(tree);
});
