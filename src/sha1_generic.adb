pragma Ada_2012;

with GNAT.Byte_Swapping;
with System;

package body SHA1_Generic is
   function Initialize return Context is
     ((State => <>, Count => 0, Buffer => (others => <>)));

   procedure Initialize (Ctx : out Context) is
   begin
      Ctx := Initialize;
   end Initialize;

   procedure Update (Ctx : in out Context; Input : String) is
      Buffer : Element_Array (Index (Input'First) .. Index (Input'Last));
      for Buffer'Address use Input'Address;
      pragma Import (Ada, Buffer);
   begin
      Update (Ctx, Buffer);
   end Update;

   procedure Update (Ctx : in out Context; Input : Element_Array) is
      Current : Index := Input'First;
   begin
      while Current <= Input'Last loop
         declare
            Buffer_Index  : constant Index := Ctx.Count rem Block_Length;
            Bytes_To_Copy : constant Index :=
              Index'Min
                (Input'Length - (Current - Input'First),
                 Ctx.Buffer'Last - Buffer_Index + 1);
         begin
            Ctx.Buffer (Buffer_Index .. Buffer_Index + Bytes_To_Copy - 1) :=
              Input (Current .. Current + Bytes_To_Copy - 1);
            Current   := Current + Bytes_To_Copy;
            Ctx.Count := Ctx.Count + Bytes_To_Copy;

            if Ctx.Buffer'Last < Buffer_Index + Bytes_To_Copy then
               Transform (Ctx);
            end if;
         end;
      end loop;
   end Update;

   function Finalize (Ctx : Context) return Digest is
      Result : Digest;
   begin
      Finalize (Ctx, Result);
      return Result;
   end Finalize;

   procedure Finalize (Ctx : Context; Output : out Digest) is
      use GNAT.Byte_Swapping;
      use System;

      Current     : Index          := Output'First;
      Final_Count : constant Index := Ctx.Count;

      Ctx_Copy : Context := Ctx;
   begin
      --  Insert padding
      Update (Ctx_Copy, Element_Array'(0 => 16#80#));

      if Ctx_Copy.Buffer'Last - (Ctx_Copy.Count rem Block_Length) < 8 then
         --  In case not enough space is left in the buffer we fill it up
         Update
           (Ctx_Copy,
            Element_Array'
              (0 ..
                   (Ctx_Copy.Buffer'Last -
                    (Ctx_Copy.Count rem Block_Length)) =>
                 0));
      end if;

      --  Fill rest of the data with zeroes
      Update
        (Ctx_Copy,
         Element_Array'
           (0 ..
                (Ctx_Copy.Buffer'Last - (Ctx_Copy.Count rem Block_Length) -
                 8) =>
              0));

      declare
         --  Shift_Left(X, 3) is equivalent to multiplyng by 8
         Byte_Length : Unsigned_64 :=
           Shift_Left (Unsigned_64 (Final_Count), 3);

         Byte_Length_Buffer : Element_Array (0 .. 7);
         for Byte_Length_Buffer'Address use Byte_Length'Address;
         pragma Import (Ada, Byte_Length_Buffer);
      begin
         if Default_Bit_Order /= High_Order_First then
            Swap8 (Byte_Length_Buffer'Address);
         end if;
         Update (Ctx_Copy, Byte_Length_Buffer);
      end;

      for H of Ctx_Copy.State loop
         declare
            Buffer : Element_Array (0 .. 3);
            for Buffer'Address use H'Address;
            pragma Import (Ada, Buffer);
         begin
            if Default_Bit_Order /= High_Order_First then
               Swap4 (Buffer'Address);
            end if;
            Output (Current + 0 .. Current + 3) := Buffer;
            Current                             := Current + 4;
         end;
      end loop;
   end Finalize;

   function Hash (Input : String) return Digest is
      Ctx : Context := Initialize;
   begin
      Update (Ctx, Input);
      return Finalize (Ctx);
   end Hash;

   function Hash (Input : Element_Array) return Digest is
      Ctx : Context := Initialize;
   begin
      Update (Ctx, Input);
      return Finalize (Ctx);
   end Hash;

   procedure Transform (Ctx : in out Context) is
      type Words is array (Unsigned_32 range <>) of Unsigned_32;

      W : aliased Words (0 .. 79);

      A : Unsigned_32 := Ctx.State (0);
      B : Unsigned_32 := Ctx.State (1);
      C : Unsigned_32 := Ctx.State (2);
      D : Unsigned_32 := Ctx.State (3);
      E : Unsigned_32 := Ctx.State (4);
   begin
      declare
         use GNAT.Byte_Swapping;
         use System;

         Buffer_Words : Words (0 .. 15);
         for Buffer_Words'Address use Ctx.Buffer'Address;
         pragma Import (Ada, Buffer_Words);
      begin
         W (0 .. 15) := Buffer_Words;

         if Default_Bit_Order /= High_Order_First then
            for I in Buffer_Words'Range loop
               Swap4 (W (I)'Address);
            end loop;
         end if;
      end;

      declare
         procedure SHA1_LOAD (I : Unsigned_32);
         procedure SHA1_ROUND_0
           (V :        Unsigned_32; U : in out Unsigned_32; X, Y : Unsigned_32;
            Z : in out Unsigned_32; I : Unsigned_32);
         procedure SHA1_ROUND_1
           (V :        Unsigned_32; U : in out Unsigned_32; X, Y : Unsigned_32;
            Z : in out Unsigned_32; I : Unsigned_32);
         procedure SHA1_ROUND_2
           (V :        Unsigned_32; U : in out Unsigned_32; X, Y : Unsigned_32;
            Z : in out Unsigned_32; I : Unsigned_32);
         procedure SHA1_ROUND_3
           (V :        Unsigned_32; U : in out Unsigned_32; X, Y : Unsigned_32;
            Z : in out Unsigned_32; I : Unsigned_32);
         procedure SHA1_ROUND_4
           (V :        Unsigned_32; U : in out Unsigned_32; X, Y : Unsigned_32;
            Z : in out Unsigned_32; I : Unsigned_32);

         procedure SHA1_LOAD (I : Unsigned_32) is
         begin
            W (I and 15) :=
              Rotate_Left
                (W ((I + 13) and 15) xor W ((I + 8) and 15) xor
                 W ((I + 2) and 15) xor W (I and 15),
                 1);
         end SHA1_LOAD;

         procedure SHA1_ROUND_0
           (V :        Unsigned_32; U : in out Unsigned_32; X, Y : Unsigned_32;
            Z : in out Unsigned_32; I : Unsigned_32)
         is
         begin
            Z :=
              Z + ((U and (X xor Y)) xor Y) + W (I and 15) + 16#5a82_7999# +
              Rotate_Left (V, 5);
            U := Rotate_Left (U, 30);
         end SHA1_ROUND_0;

         procedure SHA1_ROUND_1
           (V :        Unsigned_32; U : in out Unsigned_32; X, Y : Unsigned_32;
            Z : in out Unsigned_32; I : Unsigned_32)
         is
         begin
            SHA1_LOAD (I);
            Z :=
              Z + ((U and (X xor Y)) xor Y) + W (I and 15) + 16#5a82_7999# +
              Rotate_Left (V, 5);
            U := Rotate_Left (U, 30);
         end SHA1_ROUND_1;

         procedure SHA1_ROUND_2
           (V :        Unsigned_32; U : in out Unsigned_32; X, Y : Unsigned_32;
            Z : in out Unsigned_32; I : Unsigned_32)
         is
         begin
            SHA1_LOAD (I);
            Z :=
              Z + (U xor X xor Y) + W (I and 15) + 16#6ed9_eba1# +
              Rotate_Left (V, 5);
            U := Rotate_Left (U, 30);
         end SHA1_ROUND_2;

         procedure SHA1_ROUND_3
           (V :        Unsigned_32; U : in out Unsigned_32; X, Y : Unsigned_32;
            Z : in out Unsigned_32; I : Unsigned_32)
         is
         begin
            SHA1_LOAD (I);
            Z :=
              Z + (((U or X) and Y) or (U and X)) + W (I and 15) +
              16#8f1b_bcdc# + Rotate_Left (V, 5);
            U := Rotate_Left (U, 30);
         end SHA1_ROUND_3;

         procedure SHA1_ROUND_4
           (V :        Unsigned_32; U : in out Unsigned_32; X, Y : Unsigned_32;
            Z : in out Unsigned_32; I : Unsigned_32)
         is
         begin
            SHA1_LOAD (I);
            Z :=
              Z + (U xor X xor Y) + W (I and 15) + 16#ca62_c1d6# +
              Rotate_Left (V, 5);
            U := Rotate_Left (U, 30);
         end SHA1_ROUND_4;

         pragma Inline
           (SHA1_LOAD, SHA1_ROUND_0, SHA1_ROUND_1, SHA1_ROUND_2, SHA1_ROUND_3,
            SHA1_ROUND_4);
      begin
         SHA1_ROUND_0 (A, B, C, D, E, 0);
         SHA1_ROUND_0 (E, A, B, C, D, 1);
         SHA1_ROUND_0 (D, E, A, B, C, 2);
         SHA1_ROUND_0 (C, D, E, A, B, 3);
         SHA1_ROUND_0 (B, C, D, E, A, 4);
         SHA1_ROUND_0 (A, B, C, D, E, 5);
         SHA1_ROUND_0 (E, A, B, C, D, 6);
         SHA1_ROUND_0 (D, E, A, B, C, 7);
         SHA1_ROUND_0 (C, D, E, A, B, 8);
         SHA1_ROUND_0 (B, C, D, E, A, 9);
         SHA1_ROUND_0 (A, B, C, D, E, 10);
         SHA1_ROUND_0 (E, A, B, C, D, 11);
         SHA1_ROUND_0 (D, E, A, B, C, 12);
         SHA1_ROUND_0 (C, D, E, A, B, 13);
         SHA1_ROUND_0 (B, C, D, E, A, 14);
         SHA1_ROUND_0 (A, B, C, D, E, 15);
         SHA1_ROUND_1 (E, A, B, C, D, 16);
         SHA1_ROUND_1 (D, E, A, B, C, 17);
         SHA1_ROUND_1 (C, D, E, A, B, 18);
         SHA1_ROUND_1 (B, C, D, E, A, 19);
         SHA1_ROUND_2 (A, B, C, D, E, 20);
         SHA1_ROUND_2 (E, A, B, C, D, 21);
         SHA1_ROUND_2 (D, E, A, B, C, 22);
         SHA1_ROUND_2 (C, D, E, A, B, 23);
         SHA1_ROUND_2 (B, C, D, E, A, 24);
         SHA1_ROUND_2 (A, B, C, D, E, 25);
         SHA1_ROUND_2 (E, A, B, C, D, 26);
         SHA1_ROUND_2 (D, E, A, B, C, 27);
         SHA1_ROUND_2 (C, D, E, A, B, 28);
         SHA1_ROUND_2 (B, C, D, E, A, 29);
         SHA1_ROUND_2 (A, B, C, D, E, 30);
         SHA1_ROUND_2 (E, A, B, C, D, 31);
         SHA1_ROUND_2 (D, E, A, B, C, 32);
         SHA1_ROUND_2 (C, D, E, A, B, 33);
         SHA1_ROUND_2 (B, C, D, E, A, 34);
         SHA1_ROUND_2 (A, B, C, D, E, 35);
         SHA1_ROUND_2 (E, A, B, C, D, 36);
         SHA1_ROUND_2 (D, E, A, B, C, 37);
         SHA1_ROUND_2 (C, D, E, A, B, 38);
         SHA1_ROUND_2 (B, C, D, E, A, 39);
         SHA1_ROUND_3 (A, B, C, D, E, 40);
         SHA1_ROUND_3 (E, A, B, C, D, 41);
         SHA1_ROUND_3 (D, E, A, B, C, 42);
         SHA1_ROUND_3 (C, D, E, A, B, 43);
         SHA1_ROUND_3 (B, C, D, E, A, 44);
         SHA1_ROUND_3 (A, B, C, D, E, 45);
         SHA1_ROUND_3 (E, A, B, C, D, 46);
         SHA1_ROUND_3 (D, E, A, B, C, 47);
         SHA1_ROUND_3 (C, D, E, A, B, 48);
         SHA1_ROUND_3 (B, C, D, E, A, 49);
         SHA1_ROUND_3 (A, B, C, D, E, 50);
         SHA1_ROUND_3 (E, A, B, C, D, 51);
         SHA1_ROUND_3 (D, E, A, B, C, 52);
         SHA1_ROUND_3 (C, D, E, A, B, 53);
         SHA1_ROUND_3 (B, C, D, E, A, 54);
         SHA1_ROUND_3 (A, B, C, D, E, 55);
         SHA1_ROUND_3 (E, A, B, C, D, 56);
         SHA1_ROUND_3 (D, E, A, B, C, 57);
         SHA1_ROUND_3 (C, D, E, A, B, 58);
         SHA1_ROUND_3 (B, C, D, E, A, 59);
         SHA1_ROUND_4 (A, B, C, D, E, 60);
         SHA1_ROUND_4 (E, A, B, C, D, 61);
         SHA1_ROUND_4 (D, E, A, B, C, 62);
         SHA1_ROUND_4 (C, D, E, A, B, 63);
         SHA1_ROUND_4 (B, C, D, E, A, 64);
         SHA1_ROUND_4 (A, B, C, D, E, 65);
         SHA1_ROUND_4 (E, A, B, C, D, 66);
         SHA1_ROUND_4 (D, E, A, B, C, 67);
         SHA1_ROUND_4 (C, D, E, A, B, 68);
         SHA1_ROUND_4 (B, C, D, E, A, 69);
         SHA1_ROUND_4 (A, B, C, D, E, 70);
         SHA1_ROUND_4 (E, A, B, C, D, 71);
         SHA1_ROUND_4 (D, E, A, B, C, 72);
         SHA1_ROUND_4 (C, D, E, A, B, 73);
         SHA1_ROUND_4 (B, C, D, E, A, 74);
         SHA1_ROUND_4 (A, B, C, D, E, 75);
         SHA1_ROUND_4 (E, A, B, C, D, 76);
         SHA1_ROUND_4 (D, E, A, B, C, 77);
         SHA1_ROUND_4 (C, D, E, A, B, 78);
         SHA1_ROUND_4 (B, C, D, E, A, 79);
      end;

      Ctx.State (0) := Ctx.State (0) + A;
      Ctx.State (1) := Ctx.State (1) + B;
      Ctx.State (2) := Ctx.State (2) + C;
      Ctx.State (3) := Ctx.State (3) + D;
      Ctx.State (4) := Ctx.State (4) + E;
   end Transform;
end SHA1_Generic;
