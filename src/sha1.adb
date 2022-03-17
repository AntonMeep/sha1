pragma Ada_2012;
package body SHA1 is
   function Init return Context is
   begin
      pragma Compile_Time_Warning (Standard.True, "Init unimplemented");
      return raise Program_Error with "Unimplemented function Init";
   end Init;

   procedure Init (Ctx : out Context) is
   begin
      Ctx := Init;
   end Init;

   procedure Update (Ctx : in out Context; Input : String) is
   begin
      pragma Compile_Time_Warning (Standard.True, "Update unimplemented");
      raise Program_Error with "Unimplemented procedure Update";
   end Update;

   procedure Update (Ctx : in out Context; Input : Wide_String) is
   begin
      pragma Compile_Time_Warning (Standard.True, "Update unimplemented");
      raise Program_Error with "Unimplemented procedure Update";
   end Update;

   procedure Update (Ctx : in out Context; Input : Stream_Element_Array) is
   begin
      pragma Compile_Time_Warning (Standard.True, "Update unimplemented");
      raise Program_Error with "Unimplemented procedure Update";
   end Update;

   function Final (Ctx : Context) return Digest is
   begin
      pragma Compile_Time_Warning (Standard.True, "Final unimplemented");
      return raise Program_Error with "Unimplemented function Final";
   end Final;

   procedure Final (Ctx : Context; Output : out Digest) is
   begin
      Output := Final (Ctx);
   end Final;

   procedure Read
     (Stream : in out Hash_Stream_Type; Item : out Stream_Element_Array;
      Last   :    out Stream_Element_Offset)
   is
   begin
      raise Program_Error with "Hash_Stream_Type is write-only";
   end Read;

   procedure Write
     (Stream : in out Hash_Stream_Type; Item : in Stream_Element_Array)
   is
   begin
      Update (Stream.Ctx.all, Item);
   end Write;
end SHA1;
