package com.omnicybersecurity.authcheck.ui;

import com.omnicybersecurity.authcheck.config.Configuration;
import com.omnicybersecurity.authcheck.engine.RecordStore;
import com.omnicybersecurity.authcheck.model.AuthTestRecord;
import com.omnicybersecurity.authcheck.model.Identity;
import com.omnicybersecurity.authcheck.model.VariantResult;
import com.omnicybersecurity.authcheck.model.Verdict;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Backs the results table. The fixed columns describe the request; after them
 * comes one verdict column per variant, rebuilt whenever identities change.
 */
public final class ResultsTableModel extends AbstractTableModel {

    private static final String[] FIXED_COLUMNS = { "#", "Time", "Source", "Method", "URL", "Status", "Length" };

    /** A variant column: which result to read, and what to call it. */
    public record VariantColumn(String key, String label) {
    }

    private final RecordStore records;
    private final Configuration configuration;
    private List<VariantColumn> variants = new ArrayList<>();

    public ResultsTableModel(RecordStore records, Configuration configuration) {
        this.records = records;
        this.configuration = configuration;
        rebuildColumns(false);
    }

    /** Recomputes the variant columns from current settings and identities. */
    public void rebuildColumns(boolean fireEvent) {
        List<VariantColumn> rebuilt = new ArrayList<>();
        if (configuration.settings().testUnauthenticated()) {
            rebuilt.add(new VariantColumn(Identity.UNAUTHENTICATED_KEY, "Unauthenticated"));
        }
        for (Identity identity : configuration.identities()) {
            if (identity.enabled()) {
                rebuilt.add(new VariantColumn(identity.id(), identity.name()));
            }
        }
        this.variants = rebuilt;
        if (fireEvent) {
            fireTableStructureChanged();
        }
    }

    public List<VariantColumn> variants() {
        return variants;
    }

    /**
     * A stable identifier for a column, used to remember the sort across
     * restarts. Column <em>indices</em> shift whenever an identity is added,
     * removed or disabled, so an index would silently start meaning a different
     * column; the identity's id does not move.
     */
    public String columnKey(int column) {
        if (column < 0) {
            return "";
        }
        if (column < FIXED_COLUMNS.length) {
            return "fixed:" + FIXED_COLUMNS[column];
        }
        int variantIndex = column - FIXED_COLUMNS.length;
        if (variantIndex < variants.size()) {
            return "variant:" + variants.get(variantIndex).key();
        }
        return "fixed:Notes";
    }

    /** The current index of a remembered column, or -1 if it is gone. */
    public int columnForKey(String key) {
        if (key == null || key.isBlank()) {
            return -1;
        }
        for (int column = 0; column < getColumnCount(); column++) {
            if (columnKey(column).equals(key)) {
                return column;
            }
        }
        return -1;
    }

    public AuthTestRecord recordAt(int rowIndex) {
        return records.get(rowIndex);
    }

    @Override
    public int getRowCount() {
        return records.size();
    }

    @Override
    public int getColumnCount() {
        return FIXED_COLUMNS.length + variants.size() + 1;
    }

    @Override
    public String getColumnName(int column) {
        if (column < FIXED_COLUMNS.length) {
            return FIXED_COLUMNS[column];
        }
        int variantIndex = column - FIXED_COLUMNS.length;
        if (variantIndex < variants.size()) {
            return variants.get(variantIndex).label();
        }
        return "Notes";
    }

    @Override
    public Class<?> getColumnClass(int column) {
        if (column < FIXED_COLUMNS.length) {
            return switch (column) {
                case 0, 5, 6 -> Integer.class;
                default -> String.class;
            };
        }
        int variantIndex = column - FIXED_COLUMNS.length;
        return variantIndex < variants.size() ? Verdict.class : String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        AuthTestRecord record = records.get(rowIndex);
        if (record == null) {
            return null;
        }
        if (columnIndex < FIXED_COLUMNS.length) {
            return switch (columnIndex) {
                case 0 -> record.index();
                case 1 -> record.time();
                case 2 -> record.source();
                case 3 -> record.method();
                case 4 -> record.url();
                case 5 -> (int) record.baselineStatus();
                case 6 -> record.baselineLength();
                default -> null;
            };
        }
        int variantIndex = columnIndex - FIXED_COLUMNS.length;
        if (variantIndex < variants.size()) {
            VariantResult result = record.result(variants.get(variantIndex).key());
            return result == null ? Verdict.NOT_TESTED : result.verdict();
        }
        return record.note();
    }

    /** Detail text for a variant cell, used as the cell tooltip. */
    public String tooltipAt(int rowIndex, int columnIndex) {
        AuthTestRecord record = records.get(rowIndex);
        if (record == null) {
            return null;
        }
        int variantIndex = columnIndex - FIXED_COLUMNS.length;
        if (variantIndex >= 0 && variantIndex < variants.size()) {
            VariantResult result = record.result(variants.get(variantIndex).key());
            return result == null ? null : "<html><body style='width:420px'>" + escape(result.detail())
                    + "</body></html>";
        }
        if (columnIndex == 4) {
            return record.url();
        }
        return null;
    }

    private static String escape(String text) {
        return text == null ? "" : text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
