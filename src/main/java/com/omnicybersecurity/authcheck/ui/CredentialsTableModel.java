package com.omnicybersecurity.authcheck.ui;

import com.omnicybersecurity.authcheck.model.Identity;
import com.omnicybersecurity.authcheck.util.Text;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Editable name/value table for the credentials a script has <em>not</em>
 * declared. These are the "variables" auth scripts read through the
 * {@code creds} binding, and they are saved into the Burp project.
 *
 * <p>A script that declares its params gets a typed form instead, and this table
 * holds whatever is left over -- a key the script's author forgot to declare, or
 * one left behind by an earlier script. A script that declares nothing gets this
 * table for everything, which is how every identity worked before declarations
 * existed.
 *
 * <p>Values whose name looks secret are masked until the tester opts to show
 * them; masked cells are read-only so a mask can never be saved over a password.
 * A declared param does better than this guess -- it says outright that it is a
 * secret -- which is one of the reasons to declare.
 */
public final class CredentialsTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = { "Name", "Value" };

    private final List<String[]> rows = new ArrayList<>();
    private final Runnable onChanged;
    private boolean showValues;

    public CredentialsTableModel(Runnable onChanged) {
        this.onChanged = onChanged;
    }

    /**
     * Loads the identity's credentials, minus the ones the script declares --
     * those belong to the typed form and would otherwise appear twice.
     */
    public void load(Identity identity, Collection<String> declared) {
        rows.clear();
        if (identity != null) {
            identity.credentialsSnapshot().forEach((key, value) -> {
                if (!declared.contains(key)) {
                    rows.add(new String[] { key, value });
                }
            });
        }
        fireTableDataChanged();
    }

    /**
     * Adds or updates one row without announcing a tester edit. Used when a
     * script stops declaring a param: the value it held is still a credential of
     * this identity, and it has to land somewhere rather than disappear.
     */
    public void put(String name, String value) {
        for (int index = 0; index < rows.size(); index++) {
            if (rows.get(index)[0].equals(name)) {
                rows.get(index)[1] = Text.nullToEmpty(value);
                fireTableRowsUpdated(index, index);
                return;
            }
        }
        rows.add(new String[] { name, Text.nullToEmpty(value) });
        fireTableRowsInserted(rows.size() - 1, rows.size() - 1);
    }

    /** The table's contents, for the caller to merge with the declared fields. */
    public Map<String, String> values() {
        Map<String, String> values = new LinkedHashMap<>();
        for (String[] row : rows) {
            if (!Text.isBlank(row[0])) {
                values.put(row[0].trim(), Text.nullToEmpty(row[1]));
            }
        }
        return values;
    }

    public void addRow() {
        rows.add(new String[] { "", "" });
        fireTableRowsInserted(rows.size() - 1, rows.size() - 1);
        onChanged.run();
    }

    public void removeRow(int index) {
        if (index >= 0 && index < rows.size()) {
            rows.remove(index);
            fireTableRowsDeleted(index, index);
            onChanged.run();
        }
    }

    public void setShowValues(boolean value) {
        this.showValues = value;
        fireTableDataChanged();
    }

    public boolean isMasked(int rowIndex) {
        return !showValues && rowIndex >= 0 && rowIndex < rows.size() && Text.looksSecret(rows.get(rowIndex)[0]);
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 0 || !isMasked(rowIndex);
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        String[] row = rows.get(rowIndex);
        if (columnIndex == 0) {
            return row[0];
        }
        return isMasked(rowIndex) ? Text.mask(row[1]) : row[1];
    }

    @Override
    public void setValueAt(Object value, int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= rows.size()) {
            return;
        }
        String text = value == null ? "" : value.toString();
        if (columnIndex == 1 && isMasked(rowIndex)) {
            return;
        }
        rows.get(rowIndex)[columnIndex] = text;
        fireTableRowsUpdated(rowIndex, rowIndex);
        onChanged.run();
    }
}
