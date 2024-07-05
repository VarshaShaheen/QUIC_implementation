module quic_encoder #(parameter N = 255)(
    input wire clk,
    input wire [133:0] data,
    output reg [N-1:0] quic_data
);

localparam [127:0] AES_KEY = 128'h0123456789ABCDEF0123456789ABCDEF;
localparam [7:0] QUIC_HEADER_FORM = 8'h80;
localparam [7:0] QUIC_FIXED_BIT = 8'h40;
localparam [7:0] QUIC_TYPE = 8'h30;
localparam [63:0] QUIC_DEST_CONN_ID = 64'h0123456789ABCDEF;
localparam [63:0] QUIC_SRC_CONN_ID = 64'hFEDCBA9876543210;
localparam [95:0] NONCE = 96'h0102030405060708090A0B0C;

reg [127:0] plaintext;
reg [127:0] ciphertext;
function [127:0] encrypt(input [127:0] data, input [127:0] key, input [95:0] nonce);
begin
    encrypt = data ^ key[127:0] ^ {32'h0, nonce[95:0]};
end
endfunction

always @(posedge clk) begin
        plaintext[127:120] <= QUIC_HEADER_FORM | QUIC_FIXED_BIT | QUIC_TYPE;
        plaintext[119:56] <= QUIC_DEST_CONN_ID;
        plaintext[55:0] <= data[133:78];
        ciphertext <= encrypt(plaintext, AES_KEY, NONCE);
        
        quic_data[N-1:N-128] <= ciphertext;
        quic_data[N-129:N-194] <= QUIC_SRC_CONN_ID;
        quic_data[N-195:N-202] <= 8'h00;
        quic_data[N-203:N-210] <= 8'hFF;
        quic_data[N-211:0] <= data[77:0];
end

endmodule

