' Boat registry
Imports System
Imports System.Collections.Generic

Namespace Harbour
    Public Class Registry
        Private ReadOnly boats As New List(Of String)

        Public Sub Add(name As String)
            boats.Add(name) ' TODO: validate
        End Sub

        Public Function Count() As Integer
            Return boats.Count
        End Function
    End Class
End Namespace
