 // Generated by MyHDL 0.11
`timescale 1ns/10ps

module pass_through (
    clk,
    encoded,
    decoded,
    source_port,
    dest_port,
    data
);


input clk;
input encoded;
output [487:0] decoded;
reg [487:0] decoded;
output [15:0] source_port;
reg [15:0] source_port;
output [15:0] dest_port;
reg [15:0] dest_port;
output [133:0] data;
reg [133:0] data;
wire [255:0] quic_data;

reg trigger = 0;
reg [9:0] manchester_decoder0_i = 0;
reg [8:0] manchester_decoder0_index = 0;
reg manchester_decoder0_last_bit = 0;


// TODO: Clean up after debug
reg [15:0] ethertype_reg;
reg [7:0] protocol_reg;
reg [15:0] dest_port_original;

quic_encoder#(.N(255)) encoder (.clk(clk), .data(data), .quic_data(quic_data));

always @(posedge clk) begin: PASS_THROUGH_MANCHESTER_DECODER0_MANCHESTER_DECODE
    if (trigger) begin
        disable PASS_THROUGH_MANCHESTER_DECODER0_MANCHESTER_DECODE;
    end
    if ((manchester_decoder0_i % 2)) begin
        if ((manchester_decoder0_last_bit && (!encoded))) begin
            decoded[manchester_decoder0_index] <= 1;
        end
else if (((!manchester_decoder0_last_bit) && encoded)) begin
            decoded[manchester_decoder0_index] <= 0;
        end
        else if (((!manchester_decoder0_last_bit) && (!encoded))) begin
            trigger <= 1;
        end
        else if ((manchester_decoder0_last_bit && encoded)) begin
            $finish;
        end
        manchester_decoder0_index <= (manchester_decoder0_index + 1);
    end
    else begin
        manchester_decoder0_last_bit <= encoded;
    end
    manchester_decoder0_i <= (manchester_decoder0_i + 1);
end


always @(decoded, trigger) begin: PASS_THROUGH_IP_PARSER0_LOGIC
integer ethertype;
    integer protocol;
    integer i;
    
    if ((!trigger)) begin
        disable PASS_THROUGH_IP_PARSER0_LOGIC;
    end
    
    ethertype = decoded[392-1:(392 - 16)];
    protocol = decoded[304-1:(304 - 8)];
    
    ethertype_reg <= ethertype;
    protocol_reg <= protocol;

    
    if (((ethertype == 2048) && (protocol == 17))) begin
        source_port = decoded[216-1:(216 - 16)]; 
        dest_port_original = decoded[200-1:(200 - 16)];
        dest_port = decoded[200-1:(200 - 16)];
        
        data = decoded[166-1:32];

        decoded[166-1:32] = data;
    end
end

endmodule
